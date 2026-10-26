# frozen_string_literal: true
# Do not log parliamentary password, authenticator codes or setup credentials.
Rails.application.config.filter_parameters += [:authenticator_code, :enrolment_token, :token, :password, :password_confirmation]
