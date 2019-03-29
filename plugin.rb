# name: discourse-oauth2-cj
# about: Generic OAuth2 Plugin
# version: 0.3
# authors: Robin Ward
# url: https://github.com/fiddlerwoaroof/discourse-oauth2-basic

require_dependency 'auth/oauth2_authenticator.rb'

enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2CJ < ::OmniAuth::Strategies::OAuth2
  option :name, 'oauth2_cj'
  option :client_options, {
           :site => 'https://login.cj.com',
           :authorize_url => 'https://login.cj.com/auth',
           :token_url => 'https://login.cj.com/token',
         }

  def build_access_token
    options.token_params.merge!(:headers => {'Authorization' => basic_auth_header})
    super
  end

  def basic_auth_header
    puts options.to_hash.to_s
    "Basic " + Base64.strict_encode64("#{options[:client_id]}:#{options[:client_secret]}")
  end

  def request_phase
    super
  end

  def authorize_params
    super.tap do |params|
      %w[scope client_options].each do |v|
        if request.params[v]
          params[v.to_sym] = request.params[v]
        end
      end
    end
  end

  uid do
    decoded = ::JWT.decode(access_token.token, nil, false).first
    decoded["userId"]
  end

  extra do
    fetch_user_details(uid, access_token.token).select {|k| k != "companies"}
  end

  def callback_url
    full_host + script_name + callback_path
  end
end
OmniAuth.config.add_camelization 'oauth2_cj', 'Oauth2CJ'

class OAuth2CJAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_cj,
                      name: 'oauth2_cj',
                      setup: lambda { |env|
      opts[:client_id] = SiteSetting.oauth2_client_id
      opts[:client_secret] = SiteSetting.oauth2_client_secret
      opts[:provider_ignores_state] = false
    }
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def after_authenticate(auth)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")
    log("result #{auth.to_hash}")

    result = Auth::Result.new

    result.email = auth['extra']['emailAddress']
    result.email_valid = result.email.present? && SiteSetting.oauth2_email_verified?

    current_info = ::PluginStore.get("oauth2_cj", "oauth2_cj_user_#{auth.uid}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
      result.user&.update!(email: result.email) if SiteSetting.oauth2_overrides_email && result.email
    elsif SiteSetting.oauth2_email_verified?
      result.user = User.find_by_email(result.email)
      if result.user && user_details[:user_id]
        ::PluginStore.set("oauth2_cj", "oauth2_cj_user_#{auth.uid}", user_id: result.user.id)
      end
    end

    result.extra_data = { oauth2_cj_user_id: auth.uid }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("oauth2_cj", "oauth2_cj_user_#{auth.uid}", user_id: user.id)
  end

  def enabled?
    SiteSetting.oauth2_cj_enabled
  end
end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_cj_enabled",
              authenticator: OAuth2CJAuthenticator.new('oauth2_cj'),
              message: "OAuth2 CJ",
              full_screen_login_setting: "oauth2_full_screen_login"

register_css <<CSS

  button.btn-social.oauth2_cj {
    background-color: #00af66;
  }

CSS
