#name: discourse-ldap-auth
# about: enable ldaup authentication in discourse
# version: 0.0.1
# authors: punit


gem 'net-ldap', '0.3.1'
# 0.0.3.1 no longer in repo
#begin
	# old libraries are a pain.
	#require 'lib/pyu-ruby-sasl'
	#require 'lib/rubyntlm'
	#rescue LoadError
#end

gem 'pyu-ruby-sasl', '0.0.3.2'
gem 'rubyntlm', '0.1.1'
gem 'omniauth-ldap', '1.0.4'

enabled_site_setting :ldap_enabled

class LdapAuthenticator < ::Auth::Authenticator
	@@logger = Logger.new("#{Rails.root}/log/ldap_plugin.log")
	def name
		@@logger.info("Punit: Came to name method")
		'LDAP Authentication'
	end
	
	def after_authenticate(auth_token)
		@@logger.info("Punit: came to after_authenticate")
		result = Auth::Result.new
		puts auth_token.to_s
	end
	
	def after_create_account(user, auth)
		@@logger.info("Punit: came to after_create_account")
		data = auth[:extra_data]
		::PluginStore.set("ldap", "ldap_uid_#{data[:uid]}", {user_id: user.id })
	end
	
	def register_middleware(omniauth)
		@@logger.info("Punit: came to register middleware")
		omniauth.provider :ldap,
			:setup => lambda { |env|
              strategy = env["omniauth.strategy"]
              strategy.options[:title] = "Login to domain"
              strategy.options[:host] = SiteSetting.ldap_uri
              strategy.options[:port] = 389
              strategy.options[:method] = :plain
              strategy.options[:base] = SiteSetting.ldap_searchbase
              strategy.options[:uid] = 'sAMAccountName'
              strategy.options[:name_proc] = Proc.new {|name| name.gsub(/@.*$/,'')}
              #strategy.options[:bind_dn] = 'default_bind_dn'
           }
    end

end

auth_provider :title => 'Authenticate with AD',
    :message => 'Auth',
    :frame_width => 920,
    :frame_height => 800,
    :authenticator => LdapAuthenticator.new


