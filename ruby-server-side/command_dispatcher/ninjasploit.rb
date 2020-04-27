# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

class Console::CommandDispatcher::Ninjasploit

  Klass = Console::CommandDispatcher::Ninjasploit

  include Console::CommandDispatcher

  #
  # Initializes an instance of the priv command interaction.
  #
  def initialize(shell)
    super
  end

  #
  # List of supported commands.
  #
  def commands
    { 
      'install_hooks' => 'Install hooks to byppass defender',
      'restore_hooks' => 'Restores any previously hooked functions'
    }
  end


  def cmd_install_hooks
    res = client.Ninjasploit.install_hooks
    puts res
    true
  end

  def cmd_restore_hooks
    res = client.Ninjasploit.restore_hooks
    puts res
    true
  end


  #
  # Name for this dispatcher
  #
  def name
    'Ninjasploit'
  end


end

end
end
end
end
