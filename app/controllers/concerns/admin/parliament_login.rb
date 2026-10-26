# frozen_string_literal: true
require "digest"

module Admin::ParliamentLogin
  extend ActiveSupport::Concern

  # This authenticates Parliament's own account. It does not call GOV.UH
  # Signon, look up Government privileges, or accept Government OAuth tokens.
  def parliament_setup
    token = params[:token].to_s
    @credential = find_active_enrolment(token)
    return redirect_to(admin_login_path, alert: :invalid_login) unless @credential

    @enrolment_token = token
    @authenticator_secret = @credential.authenticator_secret
    @staff_email = @credential.admin_user.email
    protect_authentication_response
  end

  def parliament_activate
    token = params.dig(:parliament, :token).to_s
    record = find_active_enrolment(token)
    return redirect_to(admin_login_path, alert: :invalid_login) unless record

    password = params.dig(:parliament, :password).to_s
    confirmation = params.dig(:parliament, :password_confirmation).to_s
    otp = params.dig(:parliament, :authenticator_code).to_s.strip
    success = false
    if password == confirmation && password.length.between?(14, 64) && password.bytesize <= 72
      record.with_lock do
        if record.enrolment_digest == Digest::SHA256.hexdigest(token) &&
            record.enrolment_expires_at&.future? && record.password_digest.blank?
          otp_step = record.valid_totp_step(otp)
          if otp_step
            record.password = password
            record.last_totp_step = otp_step
            record.enrolment_digest = nil
            record.enrolment_expires_at = nil
            record.failed_attempts = 0
            record.locked_until = nil
            record.save!
            success = true
          end
        end
      end
    end

    if success
      reset_session
      sign_in(:user, record.admin_user, event: :authentication)
      return redirect_to admin_root_path
    end

    @credential = record
    @enrolment_token = token
    @authenticator_secret = record.authenticator_secret
    @staff_email = record.admin_user.email
    protect_authentication_response
    flash.now[:alert] = "Check your passphrase (at least 14 characters) and the current six-digit authenticator code."
    render :parliament_setup, status: :unprocessable_entity
  rescue ActiveRecord::RecordInvalid
    redirect_to admin_login_path, alert: :invalid_login
  end

  def parliament_session
    email = params.dig(:parliament, :email).to_s.downcase.strip
    password = params.dig(:parliament, :password).to_s
    otp = params.dig(:parliament, :authenticator_code).to_s.strip
    allowed = email.bytesize <= 254 && email.match?(/\A[^\s@]+@[^\s@]+\.[^\s@]+\z/)
    user = AdminUser.find_by(email: email) if allowed
    credential = ParliamentStaffCredential.find_by(admin_user_id: user.id) if user&.is_a_moderator?
    authenticated = false

    if credential
      credential.with_lock do
        if credential.password_digest.present? &&
            (credential.locked_until.nil? || credential.locked_until.past?)
          step = credential.valid_totp_step(otp) if credential.valid_password?(password)
          if step
            credential.update!(last_totp_step: step, failed_attempts: 0, locked_until: nil)
            authenticated = true
          else
            attempts = credential.failed_attempts + 1
            credential.update!(failed_attempts: attempts,
                               locked_until: attempts >= 5 ? 20.minutes.from_now : nil)
          end
        end
      end
    end

    unless authenticated
      # A uniform response does not disclose whether an account exists.
      return redirect_to admin_login_path, alert: :invalid_login
    end

    reset_session
    sign_in(:user, user, event: :authentication)
    redirect_to admin_root_path
  rescue ActiveRecord::RecordInvalid
    redirect_to admin_login_path, alert: :invalid_login
  end

  private

  def find_active_enrolment(token)
    return nil unless token.match?(/\A[A-Za-z0-9_-]{40,128}\z/)
    record = ParliamentStaffCredential.find_by(enrolment_digest: Digest::SHA256.hexdigest(token))
    return nil unless record && record.password_digest.blank? && record.enrolment_expires_at&.future?
    record
  end

  def protect_authentication_response
    response.headers["Cache-Control"] = "no-store, private"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
  end
end
