# frozen_string_literal: true
require "net/http"
require "json"
require "uri"
require "digest"
require "base64"

# Uses the already operative GOV.UH Signon OAuth 2 authorisation-code identity.
# A valid identity alone does not confer permission: Signon application access
# AND an existing moderator account are both mandatory.
module Admin::GovuhSignon
  extend ActiveSupport::Concern

  SIGNON_BASE = "https://signon.publishing.service.gov.uhrblx.com"
  CALLBACK = "https://moderate.petition.parliament.uhrblx.com/admin/govuh/callback"

  def govuh_start
    config = govuh_config
    state = SecureRandom.urlsafe_base64(32)
    verifier = SecureRandom.urlsafe_base64(48)
    session[:petitions_govuh_oauth] = {
      "state" => state,
      "verifier" => verifier,
      "created_at" => Time.current.to_i
    }
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(verifier), padding: false)
    authorize_url = URI("#{SIGNON_BASE}/oauth/authorize")
    authorize_url.query = URI.encode_www_form(
      response_type: "code",
      client_id: config.fetch("client_id"),
      redirect_uri: CALLBACK,
      state: state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    )
    redirect_to authorize_url.to_s, allow_other_host: true
  rescue Errno::ENOENT, KeyError, JSON::ParserError
    redirect_to admin_login_path, alert: :login_failed
  end

  def govuh_callback
    request_state = session.delete(:petitions_govuh_oauth)
    unless request_state.is_a?(Hash) &&
        request_state["created_at"].to_i.between?(Time.current.to_i - 600, Time.current.to_i) &&
        params[:state].is_a?(String) &&
        ActiveSupport::SecurityUtils.secure_compare(request_state.fetch("state"), params[:state]) &&
        params[:code].is_a?(String) && params[:code].size.between?(10, 2048) && params[:error].blank?
      return redirect_to admin_login_path, alert: :login_failed
    end

    config = govuh_config
    token = govuh_exchange_code(config, params[:code], request_state.fetch("verifier"))
    profile = govuh_fetch_profile(config, token).fetch("user")
    email = profile.fetch("email").to_s.downcase
    uid = profile.fetch("uid")
    permitted = uid.is_a?(String) && uid.size >= 20 &&
                profile["disabled"] == false &&
                Array(profile.fetch("permissions")).include?("signin")
    moderator = AdminUser.find_by(email: email)
    unless permitted && moderator&.is_a_moderator?
      Rails.logger.warn("GOVUH_PETITIONS_OAUTH_ROLE_DENIED")
      return redirect_to admin_login_path, alert: :login_failed
    end

    sign_in(:user, moderator, event: :authentication)
    redirect_to admin_root_path
  rescue StandardError => error
    # Never log authorisation codes, OAuth tokens, or secrets.
    Rails.logger.warn("GOVUH_PETITIONS_OAUTH_FAILED #{error.class.name}")
    redirect_to admin_login_path, alert: :login_failed
  end

  private

  def govuh_config
    # Read the existing native GOV.UH Signon application-registration receipt.
    # Only a root-readable, read-only mount is permitted; secrets never enter
    # the source repository, build layers, HTTP response or application log.
    data = File.read(Rails.root.join("storage/auth/signon-registration-output.txt"))
    identifier = data[/^config\.oauth_id\s*=\s*'([^']+)'$/, 1]
    credential = data[/^config\.oauth_secret\s*=\s*'([^']+)'$/, 1]
    raise ArgumentError unless identifier&.size&.between?(20, 255)
    raise ArgumentError unless credential&.size&.between?(32, 255)
    { "client_id" => identifier, "client_secret" => credential }
  end

  def govuh_exchange_code(config, code, verifier)
    uri = URI("#{SIGNON_BASE}/oauth/token")
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                               open_timeout: 7, read_timeout: 9) do |http|
      post = Net::HTTP::Post.new(uri)
      post.set_form_data(
        grant_type: "authorization_code",
        client_id: config.fetch("client_id"),
        client_secret: config.fetch("client_secret"),
        code: code,
        redirect_uri: CALLBACK,
        code_verifier: verifier
      )
      http.request(post)
    end
    raise "Token exchange refused" unless response.code == "200"
    result = JSON.parse(response.body)
    raise "No bearer token" unless result.fetch("access_token").size.between?(20, 4096)
    result.fetch("access_token")
  end

  def govuh_fetch_profile(config, token)
    uri = URI("#{SIGNON_BASE}/user")
    uri.query = URI.encode_www_form(client_id: config.fetch("client_id"))
    response = Net::HTTP.start(uri.host, uri.port, use_ssl: true,
                               open_timeout: 7, read_timeout: 9) do |http|
      get = Net::HTTP::Get.new(uri)
      get["Authorization"] = "Bearer #{token}"
      http.request(get)
    end
    raise "Identity read refused" unless response.code == "200"
    JSON.parse(response.body)
  end
end
