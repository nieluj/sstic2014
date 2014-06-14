require 'loader'
require 'yaml'

loader = Loader.new

(0..15).each do |i|
  puts "OP1 = #{i}"
  s =<<EOS
movh r0, 0x00
movl r0, 0x00
movh r1, 0x00
movl r1, 0x01
add r2, r0, r1
jmp #{i}, 0xab
EOS
  r = loader.assemble_string(s).encode.send.parse_result
  puts "S:%d Z:%d => 0x%4.4x" % [ r[:S], r[:Z], r[:pc] ]

  s =<<EOS
movh r0, 0x00
movl r0, 0x00
movh r1, 0x00
movl r1, 0x00
add r2, r0, r1
jmp #{i}, 0xab
EOS
  r = loader.assemble_string(s).encode.send.parse_result
  puts "S:%d Z:%d => 0x%4.4x" % [ r[:S], r[:Z], r[:pc] ]

  s =<<EOS
movh r0, 0xf0
movl r0, 0x00
movh r1, 0xf0
movl r1, 0x00
add r2, r0, r1
jmp #{i}, 0xab
EOS
  r = loader.assemble_string(s).encode.send.parse_result
  puts "S:%d Z:%d => 0x%4.4x" % [ r[:S], r[:Z], r[:pc] ]
end
