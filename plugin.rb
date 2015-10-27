#name: discourse-ldap-auth
# about: enable ldaup authentication in discourse
# version: 0.0.1
# authors: punit


gem 'net-ldap', '0.3.1'
# the gems are differnt from libraries
gem 'pyu-ruby-sasl', '0.0.3.3', :require => false
require 'sasl'
gem 'rubyntlm', '0.1.1', :require => false
require 'net/ntlm'
gem 'omniauth-ldap', '1.0.4'

enabled_site_setting :ldap_enabled

class LdapAuthenticator < ::Auth::Authenticator
	@@logger = Logger.new("#{Rails.root}/log/ldap_plugin.log")
	def name
		'ldap'
	end
	
	def after_authenticate(auth_token)
		data = auth_token[:info]
		result = Auth::Result.new
		result.username = data["nickname"]
		result.name = data["name"]
		result.email = data["email"]
		
		# want user to be activated based on ldap trust , see OmniauthCallbacksController
		user_info = User.find_by(username: result.username)
		if user_info
			result.user = user_info
		else
			result.user = User.create(username: result.username,
				name: result.name,
				email: result.email)
		end
		result.email_valid = true
		result
	end
	
	def after_create_account(user, auth)
		data = auth[:extra_data]
	end
	
	def register_middleware(omniauth)
		omniauth.provider :ldap,
			:setup => lambda { |env|
              strategy = env["omniauth.strategy"]
              strategy.options[:title] = "Login to domain"
              strategy.options[:host] = SiteSetting.ldap_uri
              strategy.options[:port] = 389
              strategy.options[:method] = :plain
              strategy.options[:base] = SiteSetting.ldap_searchbase
              strategy.options[:uid] = SiteSetting.ldap_uid
              strategy.options[:name_proc] = Proc.new {|name| name.gsub(/@.*$/,'')}
              strategy.options[:bind_dn] = SiteSetting.ldap_dn
			  strategy.options[:filter] = SiteSetting.ldap_filter
			  strategy.options[:password] = SiteSetting.ldap_pw
           }
    end

end

# regitering auth provider
auth_provider :title => 'Authenticate with AD',
    :message => 'Auth',
    :frame_width => 920,
    :frame_height => 800,
    :authenticator => LdapAuthenticator.new

