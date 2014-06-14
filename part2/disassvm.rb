#!/usr/bin/env ruby

require 'pp'

module VM
  class Instruction
    @@registry = []

    class << self
      def register(opcode, klass)
        @@registry[opcode] = klass
      end

      def factory(opcode, pc, arg)
        k = @@registry[opcode]
        raise "invalid opcode: #{opcode}" unless k
        return k.new(opcode, pc, arg)
      end
    end

    OPCODES_STRINGS = {
      0 => "set_reg",
      1 => "or_imm_reg",
      29 => "syscall",
      10 => "xor_reg",
      2 => "load_word",
      19 => "sub_reg",
      8 => "jmp",
      23 => "dec_reg"
    }

    attr_reader :pc, :arg
    def initialize(opcode, pc, arg)
      @opcode = opcode
      @pc = pc
      @arg = arg
      decode_arg
    end

    def decode_arg
      # do nothing
    end

    def to_s
      s = "[#{@pc}] "
      #s << OPCODES_STRINGS[@opcode]
    end
  end

  class SetRegister < Instruction
    # vm_sub_400d9c
    register(0, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @imm = ((@arg >> 12) & 0xffff) << 16
    end

    def to_s
      super << " R#{@rd} = #{@imm}"
    end

  end

  class OrWithImm < Instruction
    # vm_sub_400dac
    register(1, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @imm = (@arg >> 12) & 0xffff
    end

    def to_s
      super << " R#{@rd} |= #{@imm}"
    end
  end

  class Syscall < Instruction
    # vm_sub_401490
    register(29, self)

    def to_s
      super << " syscall"
    end
  end

  class XorgReg < Instruction
    # vm_sub_400c90
    register(10, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} ^= R#{@rn}"
    end
  end

  class LoadWord < Instruction
    # vm_sub_401580
    register(2, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
      @imm = (@arg >> 16) & 0xffffffff
    end

    def to_s
      super << " R#{@rd} = *W[0x%x + R#{@rn}]" % @imm
    end
  end

  class LoadByte < Instruction
    # vm_sub_4016e4
    register(4, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
      @imm = (@arg >> 16) & 0xffffffff
    end

    def to_s
      super << " R#{@rd} = *B[0x%x + R#{@rn}]" % @imm
    end
  end

  class StoreByte < Instruction
    # vm_sub_4011b4
    register(7, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
      @imm = (@arg >> 16) & 0xffffffff
    end

    def to_s
      super << " *B[0x%x + R#{@rn}] = R#@rd" % @imm
    end
  end

  class SubReg < Instruction
    # vm_sub_4008c4
    register(19, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} -= R#{@rn}"
    end
  end

  class AddReg < Instruction
    # vm_sub_400918
    register(18, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} += R#{@rn}"
    end
  end

  class AndReg < Instruction
    # vm_sub_400bd0
    register(12, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} &= R#{@rn}"
    end
  end

  class OrReg < Instruction
    # vm_sub_400c20
    register(11, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} |= R#{@rn}"
    end
  end

  class LeftShiftReg < Instruction
    # vm_sub_400b78
    register(13, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} <<= R#{@rn}"
    end
  end

  class RightShiftReg < Instruction
    # vm_sub_400b04
    register(14, self)

    def decode_arg
      @rd = (@arg >> 8) & 0xf
      @rn = (@arg >> 12) & 0xf
    end

    def to_s
      super << " R#{@rd} >>= R#{@rn}"
    end
  end

  class Jmp < Instruction
    # vm_sub_401794
    register(8, self)

    def decode_arg
      @cond_bits = (@arg >> 13) & 7
      @r = (@arg >> 9) & 0xf
      @dest = (@arg >> 16) & 0xffffffff
      @l = (@arg >> 8) & 1
    end

    def cond_bits_to_s
      case @cond_bits
      when 0
        "ALWAYS"
      when 1
        "?1"
      when 2
        "== 0"
      when 3
        "!= 0"
      when 4
        "< 0"
      when 5
        "> 0"
      when 6
        "<= 0"
      when 7
        "?7"
      else
        "??"
      end
    end

    def to_s
      super << " JMP #{@dest} if R#@r #{cond_bits_to_s} (#@l)"
    end
  end

  class DecReg < Instruction
    # vm_sub_400ce0
    register(23, self)

    def decode_arg
      @rd = (arg >> 8) & 0xf
    end

    def to_s
      super << " R#@rd--"
    end
  end

  class IncReg < Instruction
    # vm_sub_400d24
    register(22, self)

    def decode_arg
      @rd = (arg >> 8) & 0xf
    end

    def to_s
      super << " R#@rd++"
    end
  end

  class ParityReg < Instruction
    # vm_sub_40077c
    register(30, self)

    def decode_arg
      @rd = (arg >> 8) & 0xf
      @rn = (arg >> 12) & 0xf
    end

    def to_s
      super << " R#@rd = PARITY R#@rn"
    end
  end

  class SetErrorCodeZero < Instruction
    register(28, self)

    def to_s
      super << " ERROR = 0"
    end
  end

  class Decoder
    attr_reader :instructions
    ENTRY_POINT = 0x3c
    PROGRAM_END = 808

    attr_reader :entry_point, :memory, :instructions
    def initialize(data)
      @data = data
      @memory = @data.unpack('C*')
      @instructions = []
      @entry_point = rd(ENTRY_POINT)
    end

    def decode
      @pc = @entry_point
      while @pc < PROGRAM_END
        di = decode_instruction
        @instructions << di
      end
    end

    def rw(addr)
      @memory[addr, 2].pack('C2').unpack('S').first
    end

    def rb(addr)
      @memory[addr]
    end

    def rd(addr)
      @memory[addr, 4].pack('C4').unpack('L').first
    end

    def decode_instruction
      opcode = rb(@pc)
      len = (opcode > 8) ? 2 : 4
      case len
      when 2
        arg = rw(@pc)
      when 4
        arg = rd(@pc)
      end
      di = Instruction.factory(opcode, @pc, arg)
      @pc += len
      return di
    end

  end
end

data = File.open(ARGV.shift, "rb").read
decoder = VM::Decoder.new(data)

decoder.decode
decoder.instructions.each do |di|
  puts di
end
