# -*- coding: binary -*-
module Rex
  module Post
    module Meterpreter
      module Extensions
        module Ninjasploit
          TLV_TYPE_NINJASPLOIT_INSTALL_HOOKS = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 1)
          TLV_TYPE_NINJASPLOIT_RESTORE_HOOKS = TLV_META_TYPE_STRING | (TLV_EXTENSIONS + 2)
        end
      end
    end
  end
end
    
