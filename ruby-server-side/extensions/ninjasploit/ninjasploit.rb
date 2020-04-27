# -*- coding: binary -*-
require_relative 'tlv'

module Rex
module Post
module Meterpreter
module Extensions
module Ninjasploit
class Ninjasploit < Extension
  def initialize(client)
    super(client, 'Ninjasploit')

    client.register_extension_aliases(
      [
        {
          'name' => 'Ninjasploit',
          'ext'  => self
        },
      ])
  end

  def install_hooks
    request = Packet.create_request('ninjasploit_install_hooks')

    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_NINJASPLOIT_INSTALL_HOOKS)
  end

  def restore_hooks
    request = Packet.create_request('ninjasploit_restore_hooks')

    response = client.send_request(request)

    response.get_tlv_value(TLV_TYPE_NINJASPLOIT_RESTORE_HOOKS)
  end

end

end
end
end
end
end
