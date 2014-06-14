#!/usr/bin/env ruby

require 'tempfile'
require 'optparse'
require 'ostruct'
require 'pp'
require 'socket'
require 'yaml'

class Instruction
  @@registry = {}

  class << self
    def register(opcode, klass)
      @@registry[opcode] = klass
    end

    def factory(pc, opcode, op0 = nil, op1 = nil)
      k = @@registry[opcode]
      raise "invalid opcode: #{opcode}" unless k
      return k.new(pc, opcode, op0, op1)
    end
  end

  attr_accessor :pc, :opcode, :op0, :op1
  def initialize(pc, opcode, op0 = nil, op1 = nil)
    @pc = pc
    @opcode = opcode
    @op0 = op0
    @op1 = op1
  end

  def assemble
    [ (@opcode << 4) | @op0, @op1 ]
  end

end

class FaultInstruction < Instruction
  def initialize(pc, opcode)
    @pc = pc
    @opcode = 0
    @op0 = 0
    @op1 = 0
  end
end

class ThreeRegsIns < Instruction

  attr_accessor :rd, :r0, :r1
  def decode
    @rd = @op0 & 0xf
    @r0 = (@op1 >> 4) & 0xf
    @r1 = @op1 & 0xf
  end

  def assemble
    @op0 = @rd
    @op1 = (@r0 << 4) | @r1
    super
  end

end

class RegImmIns < Instruction
  attr_accessor :rd, :imm
  def decode
    @rd = @op0
    @imm = @op1
  end

  def assemble
    @op0 = @rd
    @op1 = @imm
    super
  end
end

class UnkIns < ThreeRegsIns
  register(0, self)

  def to_s
    "unk r#@rd, r#@r0, r#@r1"
  end
end

class MovlIns < RegImmIns
  register(1, self)

  def to_s
    "movl r#@rd, 0x%x" % @imm
  end
end

class MovhIns < RegImmIns
  register(2, self)

  def to_s
    "movh r#@rd, 0x%x" % @imm
  end
end

class XorIns < ThreeRegsIns
  register(3, self)

  def to_s
    "xor r#@rd, r#@r0, r#@r1"
  end
end

class OrIns < ThreeRegsIns
  register(4, self)

  def to_s
    "or r#@rd, r#@r0, r#@r1"
  end
end

class AndIns < ThreeRegsIns
  register(5, self)

  def to_s
    "and r#@rd, r#@r0, r#@r1"
  end
end

class AddIns < ThreeRegsIns
  register(6, self)

  def to_s
    "add r#@rd, r#@r0, r#@r1"
  end
end

class SubIns < ThreeRegsIns
  register(7, self)

  def to_s
    "sub r#@rd, r#@r0, r#@r1"
  end
end

class ImulIns < ThreeRegsIns
  register(8, self)

  def to_s
    "imul r#@rd, r#@r0, r#@r1"
  end
end

class IdivIns < ThreeRegsIns
  register(9, self)

  def to_s
    "idiv r#@rd, r#@r0, r#@r1"
  end
end

class JmpStyleIns < Instruction
  attr_accessor :mode, :cond, :imm, :target
  def decode
    @mode = (@op0 >> 2) & 3
    @imm = ((@op0 & 3) << 8) | @op1
    if @imm[9] == 1 then
      @imm |= 0xfc00
    end
    @target = (@pc + 2 + @imm) & 0xffff
    @cond = case @mode
            when 0  ; "Z"
            when 1  ; "NZ"
            when 2 ; "S"
            when 3 ; "NS"
            end
  end

  def assemble
    if @target then
      @imm = (@target - @pc - 2) & 0xffff

      # JMP always
      @mode = 0
      case @cond
      when "Z"  ; @mode = 0
      when "NZ" ; @mode = 1
      when "S"  ; @mode = 2
      when "NS" ; @mode = 3
      end

      @op0 = ((@mode & 3) << 2) | (@imm >> 8) & 3
      @op1 = @imm & 0xff
    end

    super
  end

end

class JmpCondIns < JmpStyleIns
  register(10, self)

  def to_s
    "jmp #@cond, loc_%x" % (@target)
  end

end

class JmpAlwaysIns < JmpStyleIns
  register(11, self)

  def to_s
    "jmp loc_%x" % (@target)
  end

end

class CallIns < JmpStyleIns
  register(12, self)

  def to_s
    if ((@op0 >> 3) & 1) == 1 then
      "syscall #@imm"
    else
      "call sub_%x" % (@target)
    end
  end

end

class RetIns < JmpStyleIns
  register(13, self)

  def to_s
    "ret #@op0, 0x%x" % (@op1)
  end

end

class LoadByte < ThreeRegsIns
  register(14, self)

  def to_s
    "ldrb r#@rd, [r#@r0 + r#@r1]"
  end
end

class RawIns < Instruction
end

class StoreByte < ThreeRegsIns
  register(15, self)

  def to_s
    #"mov BYTE PTR [r#@r0 + r#@r1], r#@rd"
    "strb r#@rd, [r#@r0 + r#@r1]"
  end
end

class Loader
  IP = "178.33.105.197"
  PORT = 10101

  OPCODE_FROM_INS = { "unk" => 0, "movl" => 1, "movh" => 2, "xor" => 3,
                     "or" => 4, "and" => 5, "add" => 6, "sub" => 7,
                     "imul" => 8, "idiv" => 9, "jmp_cond" => 10, "jmp" => 11,
                     "call" => 12, "ret" => 13, "ldrb" => 14, "strb" => 15}

  attr_reader :binary, :instructions, :asm, :prog, :result
  def initialize(path = nil)
    @path = path
    @instructions = []
    @binary = []
    @asm = ""
    @prog = ""
  end

  def decode(output = nil)
    #puts "[+] decoding"
    @binary = []
    @prog = File.open(@path, "rb").read if @prog.empty?
    @prog.each_line do |line|
      line.strip!

      if line =~ /^:(..)(....)(..)(.*)(..)$/ then
        len, addr, flags, data, checksum = $1, $2, $3, $4, $5
        @binary += data.scan(/../).map {|x| x.to_i(16) }
      end
    end
    if output then
      File.open(output, "wb") do |f|
        f.write @binary.pack('C*')
      end
    end
    self
  end

  def encode(output = nil)
    #puts "[+] encoding"
    @binary = File.read(@path).unpack('C*') if @binary.empty?

    tmp = @binary.dup
    addr = 0
    @prog = ""
    while not tmp.empty?
      a = ":"
      line = tmp.shift(16)

      b = ([ line.size, addr, 0] + line).pack('CnC*').unpack('C*')
      cksum = b.inject(0) {|cksum, x| (cksum - x) & 0xff }

      a << "%2.2X" % line.size
      a << "%4.4X" % addr
      a << "%2.2X" % 0
      a << line.map {|c| "%2.2X" % c}.join
      a << "%2.2X" % cksum
      @prog << a + "\n"
      addr += line.size
    end
    @prog << ":00000001FF"
    @prog

    if output then
      File.open(output, "wb") do |f|
        f.write @prog
      end
    end
    self
  end

  def patch(patches)
    puts "[+] patching"
    patches.each do |addr, v|
      addr = ( addr =~ /^0x/ ) ? addr.to_i(16) : addr.to_i
      v = (v =~ /^0x/) ? v.to_i(16) : v.to_i
      orig_v = @binary[addr]
      puts "[0x%2.2x] 0x%2.2x -> 0x%2.2x" % [ addr, orig_v, v ]
      @binary[addr] = v
    end
  end

  def send
    #puts "[+] sending"
    s = TCPSocket.new IP, PORT

    @prog = File.open(@path, "rb").read if @prog.empty?
    @prog.each_line do |line|
      s.send line, 0
    end

    @result = ""
    while line = s.gets
      @result << line
    end
    s.close
    self
  end

  def test_ins(addr)
    puts "[+] testing ins at address 0x%x : 0x%2.2x 0x%2.2x" %
      [addr, @binary[addr], @binary[addr + 1]]
    orig_binary = @binary.dup
    @binary[addr] = 0
    e1 = encode.send.parse_result

    @binary = orig_binary
    @binary[addr + 2] = 0
    encode
    e2 = encode.send.parse_result

    puts "Differences:"
    diff_exceptions(e1, e2)
  end

  def parse_result
    puts @result.inspect
    return nil unless @result.include?("Exception occurred")
    r = {}
    @result.each_line do |line|
      case line
      when /Exception occurred at (\h+): (.+)$/
        r[:exception_addr] = $1.to_i(16)
        r[:exception_msg] = $2
      when /pc:(\h+) fault_addr:(\h+) \[S:(\d) Z:(\d)\] Mode:([^\s]+)/
        r[:pc] = $1.to_i(16)
        r[:fault_addr] = $2.to_i(16)
        r[:S] = $3.to_i
        r[:Z] = $4.to_i
        r[:mode] = $5
      when /r(\d+):(\h+)\s+r(\d+):(\h+)\s+r(\d+):(\h+)\s+r(\d+):(\h+)/
        r["r#{$1}".to_sym] = $2.to_i(16)
        r["r#{$3}".to_sym] = $4.to_i(16)
        r["r#{$5}".to_sym] = $6.to_i(16)
        r["r#{$7}".to_sym] = $8.to_i(16)
      end
    end
    r
  end

  def diff_exceptions(e1, e2)
    keys = (0..15).map {|x| "r#{x}".to_sym }
    keys += %i{ pc fault_addr S Z mode exception_addr }

    keys.each do |k|
      v1, v2 = e1[k], e2[k]
      if v1 != v2 then
        puts "#{k}\t: 0x%x => 0x%x" % [ v1, v2 ]
      end
    end

    v1, v2 = e1[:exception_msg], e2[:exception_msg]
    if v1 != v2 then
      puts "exception message: #{v1} => #{v2}"
    end
  end

  def disas(output, entry_points = nil)
    @instructions = {}
    @labels = {}
    @asm = ""

    puts "[+] disassembling"
    if @binary.empty? then
      puts "[+] loading binary data from #@path"
      @binary = File.read(@path).unpack('C*')
    end

    todo = entry_points || [ 0 ]
    todo = [ 0 ] if todo.empty?

    while not todo.empty?
      addr = todo.shift
      next if @instructions[addr]

      opcode, op1 = @binary[addr, 2]
      op0 = opcode & 0xf
      opcode = (opcode >> 4) & 0xf
      ins = Instruction.factory(addr, opcode, op0, op1)
      ins.decode
      @instructions[addr] = ins

      case ins
      when RetIns
        # do nothing
      when CallIns
        @labels[ins.target] = "sub_%x" % ins.target
        todo << (addr + 2) << ins.target
      when JmpAlwaysIns
        @labels[ins.target] = "loc_%x" % ins.target
        todo << ins.target
      when JmpCondIns
        @labels[ins.target] = "loc_%x" % ins.target
        todo << (addr + 2 ) << ins.target
      else
        todo << (addr + 2)
      end
    end

    pc = 0
    while true
      opcode, op1 = @binary[pc, 2]
      break unless opcode
      if l = @labels[pc] then
        @asm << "\n#{l}:\n"
      end
      if ins = @instructions[pc] then
        @asm << ins.to_s << "\t; loc_%x : 0x%2.2x 0x%2.2x\n" % [ ins.pc, ins.opcode << 4 | ins.op0, ins.op1 ]
        @asm << "\n" if ins.instance_of?(RetIns)
      else
        @asm << "db 0x%x, 0x%x\t; loc_%x\n" % [ opcode, op1, pc ]
      end
      pc += 2
    end

    if output then
      File.open(output, "wb") do |f|
        f.write @asm
      end
    end

    self
  end

  def assemble(output = nil)
    #puts "[+] assembling"
    @asm = File.open(@path, "rb").read if @asm.empty?
    parse_labels
    parse_instructions

    if output then
      File.open(output, "wb") do |f|
        f.write @binary.pack('C*')
      end
    end
    self
  end

  def assemble_string(s)
    @asm = s
    assemble
  end

  def parse_labels
    pc = 0
    lcount = 0
    @labels = {}

    @asm.each_line do |line|
      line = line.strip
      lcount += 1
      next if line =~ /^\s*;/ or line.empty?

      case line
      when /^(xor|or|and|add|sub|imul|idiv|unk|movh|movl|call|syscall|jmp|test|ret|mov|ldrb|strb|fault|db) /
        pc += 2
      when /^([^:]+):/
        label = $1
        if @labels.has_key?(label) then
          raise "line #{lcount}: duplicate label #{label}"
        end
        @labels[label] = pc
      else
        raise "line #{lcount}: invalid line '#{line}'"
      end
    end
  end

  def parse_instructions
    pc = 0
    @binary = []
    @instructions = []

    count = 0

    @asm.each_line do |line|
      count += 1
      line = line.strip
      next if line =~ /^\s*;/ or line =~ /^([^:\s]+):/ or line.empty?

      case line
      when /^(xor|or|and|add|sub|imul|idiv) r(\d+), r(\d+), r(\d+)/ then
        opcode = OPCODE_FROM_INS[$1]
        ins = Instruction.factory(pc, opcode)
        ins.rd = $2.to_i
        ins.r0 = $3.to_i
        ins.r1 = $4.to_i
      when /^(movh|movl) r(\d+), (0x[0-9a-f]+)/
        opcode = OPCODE_FROM_INS[$1]
        ins = Instruction.factory(pc, opcode)
        ins.rd = $2.to_i
        ins.imm = $3.to_i(16)
      when /^jmp (\d+), 0x(\h+)/
        opcode = OPCODE_FROM_INS["jmp_cond"]
        ins = Instruction.factory(pc, opcode)
        ins.mode = $1.to_i
        ins.imm = $2.to_i(16)
      when /^jmp ([^,]+), ([^\s]+)/
        opcode = OPCODE_FROM_INS["jmp_cond"]
        ins = Instruction.factory(pc, opcode)
        target = @labels[$2]
        raise "Unknown label: #{$2}" unless target
        ins.target = target
        ins.cond = $1
      when /^(call|jmp) ([^\s]+)/
        opcode = OPCODE_FROM_INS[$1]
        ins = Instruction.factory(pc, opcode)
        target = @labels[$2]
        raise "Unknown label: #{$2}" unless target
        ins.target = target
      when /^(movh|movl) r(\d+), (0x[0-9a-f]+)/
        opcode = OPCODE_FROM_INS[$1]
        ins = Instruction.factory(pc, opcode)
        ins.rd = $2.to_i
        ins.imm = $3.to_i(16)
      when /^(ldrb|strb) r(\d+), \[r(\d+) \+ r(\d+)\]/
        opcode = OPCODE_FROM_INS[$1]
        ins = Instruction.factory(pc, opcode)
        ins.rd = $2.to_i
        ins.r0 = $3.to_i
        ins.r1 = $4.to_i
      when /^ret (\d+), (0x[0-9a-f]+)/
        opcode = OPCODE_FROM_INS["ret"]
        ins = Instruction.factory(pc, opcode, $1.to_i, $2.to_i(16))
      when /^syscall (\d+)/
        opcode = OPCODE_FROM_INS["call"]
        ins = Instruction.factory(pc, opcode, 8, $1.to_i)
      when /^db 0x(\h+), 0x(\h+)/
        opcode = $1.to_i(16)
        op0 = opcode & 0xf
        opcode = (opcode >> 4) & 0xf
        op1 = $2.to_i(16)
        ins = RawIns.new(pc, opcode, op0, op1)
      when /^fault/
        ins = FaultInstruction.new(pc)
      else
        raise "unhandled line #{count}: #{line}"
      end

      if ins then
        @instructions << ins
        @binary += ins.assemble
        pc += 2
      else
        raise "no instruction for line #{line}"
      end

    end

  end

end

if __FILE__ == $PROGRAM_NAME

options = OpenStruct.new
options.patches = []

opt_parser = OptionParser.new do |opts|
  opts.banner = "Usage: loader.rb [options]"

  opts.on("-i", "--input FILE", "Specify input file") do |file|
    options.input = file
  end

  opts.on("-d", "--decode [OUTPUT]", "Decode a program to binary data") do |output|
    options.do_decode = true
    options.decode_output = output
  end

  opts.on("-e", "--encode [OUTPUT]", "Encode a program from binary data") do |output|
    options.do_encode = true
    options.encode_output = output
  end

  opts.on("-s", "--send", "Send and execute a program") do
    options.do_send = true
  end

  opts.on("-a", "--assemble [OUTPUT]", "Assemble a program from asm source") do |output|
    options.do_assemble = true
    options.assemble_output = output
  end

  opts.on("-p", "--patch ADDR1=V1, ADDR2=V2", "Patch specified addresses") do |patches|
    options.do_patch = true
    options.patches = patches.split(/\s*,\s*/).map {|x| x.split(/\s*=\s*/)}
  end

  opts.on("-x", "--disas [OUTPUT]", "Disassemble a program from binary data") do |output|
    options.do_disas = true
    options.disas_output = output
  end

  opts.on("-u", "--entrypoints ADDR1, ADDR2", "Specify entry points for disas") do |ep|
    options.entry_points = ep.split(/\s*,\s*/).map {|x| x.to_i(16) }
  end

  opts.on("-t", "--test [ADDR]", "Show difference before and after executing instruction at specified addr") do |addr|
    options.do_test = true
    if addr =~ /^0x/ then
      options.test_addr = addr.to_i(16)
    else
      options.test_addr = addr.to_i
    end
  end

  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit
  end
end.parse!

unless options.input then
  $stderr.puts "Missing input file, exiting ..."
  exit
end

loader = Loader.new(options.input)

if options.do_decode then
  loader.decode(options.decode_output)
end

if options.do_disas then
  loader.disas(options.disas_output, options.entry_points)
end

if options.do_patch then
  loader.patch(options.patches)
end

if options.do_test then
  loader.test_ins(options.test_addr)
end

if options.do_assemble then
  loader.assemble(options.assemble_output)
end

if options.do_encode then
  loader.encode(options.encode_output)
end

if options.do_send then
  puts loader.send.result
end

end

