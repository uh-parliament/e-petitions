# frozen_string_literal: true
Rails.application.config.filter_parameters += [:code, :state, :code_verifier]
