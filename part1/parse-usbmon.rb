#!/usr/bin/env ruby

require 'pp'

module USB

  class BinaryScanner
    attr_reader :data
    def initialize(data)
      @data = data
    end

    def empty?
      @data == nil or @data.empty?
    end

    def scan_dword
      dw = @data[0, 4].unpack('L').shift
      @data = @data[4..-1]
      return dw
    end

    def scan_data(size)
      d = @data[0, size]
      @data = @data[size..-1]
      return d
    end
  end

  class AdbMessage

    class << self
      def handle_data(binary)
        send_result, send_fname = nil, nil
        scanner = BinaryScanner.new(binary)

        while not scanner.empty?
          case cmd = scanner.scan_data(4)
          when "STAT"
            fname_size = scanner.scan_dword
            fname = scanner.scan_data(fname_size)
            st_id = scanner.scan_data(4)
            raise unless st_id == "STAT"
            st_mode, st_size, st_time = scanner.scan_dword, scanner.scan_dword,
              scanner.scan_dword
            puts "\n=> STAT \"#{fname}\": mode = #{st_mode.to_s(8)}, size = #{st_size}, time = #{Time.at(st_time)}"
          when "DONE"
            dw = scanner.scan_dword
            if dw != 0 and send_fname then
              puts "=> DONE, writing #{send_result.size} bytes to #{send_fname}, mtime = #{Time.at(dw)}"
              File.open(send_fname, "wb") do |f|
                f.write send_result
              end
              send_fname, send_result = nil, nil
            end
          when "LIST"
            fname_size = scanner.scan_dword
            fname = scanner.scan_data(fname_size)
            puts "\n=> LIST \"#{fname}\""

            cmd2 = scanner.scan_data(4)
            while cmd2 == "DENT" do
              de_mode, de_size, de_mtime, de_fname_size = scanner.scan_dword, scanner.scan_dword,
                scanner.scan_dword, scanner.scan_dword
              fname = scanner.scan_data(de_fname_size)
              puts "#{de_mode.to_s(8)}\t#{de_size}\t#{Time.at(de_mtime)} #{fname}"
              cmd2 = scanner.scan_data(4)
            end
            # NULL DENT
            raise unless cmd2.to_i == 0
            4.times { |i| scanner.scan_dword }
          when "SEND"
            send_result = ""
            ssize = scanner.scan_dword
            s = scanner.scan_data(ssize)
            puts "=> SEND #{s}"
            send_fname = File.basename(s.split(',').first)
          when "DATA"
            size = scanner.scan_dword
            puts "=> DATA #{size}"
            send_result << scanner.scan_data(size)
          when "OKAY"
            #puts "=> OKAY"
            res = scanner.scan_dword
            raise unless res == 0
          when "QUIT"
            #puts "=> QUIT"
            res = scanner.scan_dword
            raise unless res == 0
          else
            puts "Unknown command #{cmd}"
            break
          end
        end
      end
    end

    attr_accessor :command, :arg0, :arg1, :data_length, :data_check, :magic, :data
    def initialize(command, arg0, arg1, data_length, data_check, magic, data = nil)
      @command = command
      @arg0 = arg0
      @arg1 = arg1
      @data_length = data_length
      @data_check = data_check
      @magic = magic
      @data = data
    end

    def got_data?
      @data_length == @data.size
    end

    def to_s
      s = "[ADB] #@command #@arg0 #@arg1 #@data_length"
      case @command
      when "OPEN"
        s << " = " << @data
      when "WRTE"
        s << " = " << @data[0, 32].inspect
        if @data.size > 32 then
          s << " ..."
        end
      end
      return s
    end
  end

  class Event

    attr_accessor :urb_tag, :timestamp, :event_type, :address,
      :urb_type, :urb_direction, :bus_number, :device_addr, :endpoint_number,
      :urb_status, :urb_interval, :data_tag, :data_length
    attr_reader :data

    def initialize(urb_tag, timestamp, event_type, address, urb_status, data_length, data_tag)
      @urb_tag = urb_tag
      @timestamp = timestamp
      @event_type = event_type
      @address = address
      s, @bus_number, @device_addr, @endpoint_number = @address.split(':', 4)
      @urb_type = s[0,1]
      @urb_direction = s[1,1]
      if urb_status =~ /([^:]+):(.*)/ then
        @urb_status = $1
        @urb_interval = $2
      else
        @urb_status = @urb_status
      end
      @data_length = data_length.to_i
      @data_tag = data_tag
    end

    def is_submission?
      @event_type == "S"
    end

    def is_callback?
      @event_type == "C"
    end

    def is_submission_error?
      @event_type == "E"
    end

    def is_data?
      @data_tag == "="
    end

    def is_bulk?
      @urb_type == "B"
    end

    # "in" from the host's perspective => sink for adbd
    def is_bulk_in?
      @urb_type == "B" and @urb_direction == "i"
    end

    # "out" from the host's perspective => source for adbd
    def is_bulk_out?
      @urb_type == "B" and @urb_direction == "o"
    end

    def data_words=(words)
      @words = words
      @data = words.map {|x| [x].pack("H*")}.join
    end

    def to_s
      @data
    end

    def to_adb_message
      return nil unless is_data? and is_bulk?

      command = @data[0, 4]
      arg0, arg1, data_length, data_crc32, magic = *@data[4, 20].unpack('L5')
      data = @data[24..-1]
      message = AdbMessage.new(command, arg0, arg1, data_length, data_crc32, magic, data)
    end
  end

  class EventParser
    class << self
      def parse_line(line)
        raise unless line =~ /^ffff/
        comps = line.strip.split(/\s+/)
        urb_tag = comps.shift
        timestamp = comps.shift
        event_type = comps.shift
        address = comps.shift
        urb_status = comps.shift
        data_length = comps.shift
        data_tag = comps.shift

        e = Event.new(urb_tag, timestamp, event_type, address, urb_status,
                      data_length, data_tag)

        if e.is_data? then
          e.data_words = comps
        end
        return e
      end
    end
  end

end

valid_adb_commands = %w{ SYNC CNXN AUTH OPEN OKAY CLSE WRTE }

input = ARGV.shift

unless input and File.exist?(input)
  $stderr.puts "usage: parse-usbmon.rb usbtrace"
  exit
end

adb_messages = []
current_message = nil
File.open(input, "r").each_line do |line|
  next unless line =~ /^ffff/

  e = USB::EventParser.parse_line(line)
  next unless e.is_data? and e.is_bulk?

  if current_message then
    current_message.data << e.data
  else
    if e.data_length >= 4 then
      if valid_adb_commands.include?(e.data[0, 4]) then
        current_message = e.to_adb_message
      end
    end
  end

  if current_message and current_message.got_data? then
    adb_messages << current_message
    current_message = nil
  end
end

binary, shell_cmd = "", false
adb_messages.each do |m|

  case m.command
  when "OPEN"
    if m.data[0,5] == "sync:" then
      binary = ""
    elsif m.data[0,5] == "shell" then
      binary = ""
      puts "$ #{m.data.strip}"
      shell_cmd = true
    end
  when "CLSE"
    if shell_cmd then
      puts binary.strip
      shell_cmd = false
    else
      USB::AdbMessage.handle_data(binary) unless binary.empty?
    end
    binary = ""
  when "WRTE"
    binary << m.data
  end
end
