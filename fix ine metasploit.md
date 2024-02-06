Error with ine module:

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info={})

[*] The following Error was encountered: NoMethodError undefined method `cmd_exec' for #<Msf::Modules::Post__Multi__Gather__Ping_sweep::MetasploitModule:0x00007fad224a0750>

BAD
class MetasploitModule < Msf::Post


  def initialize(info={})


/usr/share/metasploit-framework/modules# nano /usr/share/metasploit-framework/modules/post/multi/gather/ping_sweep.rb
