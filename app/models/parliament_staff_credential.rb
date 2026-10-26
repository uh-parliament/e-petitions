# frozen_string_literal: true
require "bcrypt"
require "openssl"
require "digest"

# Institutional staff authentication independent of GOV.UH Signon.
# Password hashes and encrypted authenticator secrets are stored in the
# parliamentary petitions database, not in Government identity services.
class ParliamentStaffCredential < ActiveRecord::Base
  belongs_to :admin_user

  ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".freeze

  def self.new_authenticator_secret
    SecureRandom.random_bytes(20).unpack1("B*").scan(/.{1,5}/).map do |bits|
      ALPHABET[bits.ljust(5, "0").to_i(2)]
    end.join
  end

  def self.cipher
    key = Rails.application.key_generator.generate_key("uh-parliament-petitions-totp-aes-gcm-v1", 32)
    ActiveSupport::MessageEncryptor.new(key, cipher: "aes-256-gcm")
  end

  def authenticator_secret
    self.class.cipher.decrypt_and_verify(totp_ciphertext)
  end

  def authenticator_secret=(plain)
    self.totp_ciphertext = self.class.cipher.encrypt_and_sign(plain)
  end

  def valid_password?(plain)
    return false if password_digest.blank? || !plain.is_a?(String) || plain.bytesize > 256
    BCrypt::Password.new(password_digest).is_password?(plain)
  end

  def password=(plain)
    raise ArgumentError, "Password must have 14 to 128 characters" unless plain.is_a?(String) && plain.length.between?(14, 64) && plain.bytesize <= 72
    self.password_digest = BCrypt::Password.create(plain, cost: 12).to_s
  end

  def self.totp_value(secret, step)
    bits = secret.chars.map { |c| ALPHABET.index(c)&.to_s(2)&.rjust(5, "0") }.join
    bytes = bits.scan(/.{8}/).map { |byte| byte.to_i(2) }.pack("C*")
    digest = OpenSSL::HMAC.digest("sha1", bytes, [step].pack("Q>"))
    index = digest.getbyte(-1) & 15
    code = (digest.byteslice(index, 4).unpack1("N") & 0x7fffffff) % 1_000_000
    format("%06d", code)
  end

  def valid_totp_step(code, now: Time.current)
    return nil unless code.is_a?(String) && code.match?(/\A[0-9]{6}\z/)
    current = now.to_i / 30
    secret = authenticator_secret
    (current - 1..current + 1).find do |step|
      step >= 0 && (last_totp_step.nil? || step > last_totp_step) &&
        ActiveSupport::SecurityUtils.secure_compare(self.class.totp_value(secret, step), code)
    end
  end
end
