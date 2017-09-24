require 'jwt'

module Knock
  class AuthToken
    attr_reader :token
    attr_reader :payload

    InvalidClientKeyError = Class.new(ArgumentError)

    def initialize payload: {}, token: nil, verify_options: {}
      if token.present?
        decode_token token, verify_options
      else
        encode_token payload, token
      end
    end

    def decode_token(token, verify_options)
      payload, error = nil

      decode_keys.each do |(client_key, decode_key)|
        begin
          opts = options(client_key).merge(verify_options)
          payload, _ = JWT.decode token.to_s, decode_key, true, opts
          break
        rescue => err
          error = err.freeze
        end
      end

      raise error unless payload
      @payload, @token = payload, token
    end

    def encode_token(payload, token)
      @payload = claims.merge(payload)
      @token = JWT.encode @payload,
        secret_key,
        token_signature_algorithm
    end

    def entity_for entity_class
      if entity_class.respond_to? :from_token_payload
        entity_class.from_token_payload @payload
      else
        entity_class.find @payload['sub']
      end
    end

    def to_json options = {}
      {jwt: @token}.to_json
    end

  private

    def secret_key(client_key = 0)
      return unless keys = secret_keys
      keys[client_key] or raise InvalidClientKeyError
    end

    def secret_keys
      key_or_keys = Knock.token_secret_signature_key
      key_or_keys = key_or_keys.call if key_or_keys.respond_to? :call

      case key_or_keys
      when Hash
        key_or_keys
      when Array
        Hash[key_or_keys.map.with_index{|key, i| [i, key] }]
      else
        { 0 => key_or_keys } unless key_or_keys.blank?
      end
    end

    def public_keys
      key_or_keys = Knock.token_public_key
      key_or_keys = key_or_keys.call if key_or_keys.respond_to? :call

      case key_or_keys
      when Hash
        key_or_keys
      when Array
        Hash[key_or_keys.map.with_index{|key, i| [i, key] }]
      else
        { 0 => key_or_keys } unless key_or_keys.blank?
      end
    end

    def decode_keys
      (secret_keys || {}).merge(public_keys || {})
    end

    def options(client_key)
      verify_claims(client_key).merge({
        algorithm: token_signature_algorithm(client_key)
      })
    end

    def token_signature_algorithm(client_key = 0)
      return unless algos = token_signature_algorithms
      algos[client_key] or raise InvalidClientKeyError
    end

    def token_signature_algorithms
      algo_or_algos = Knock.token_signature_algorithm
      algo_or_algos = algo_or_algos.call if algo_or_algos.respond_to? :call

      case algo_or_algos
      when Hash
        algo_or_algos
      when Array
        Hash[algo_or_algos.map.with_index{|algo, i| [i, algo] }]
      else
        { 0 => algo_or_algos } unless algo_or_algos.blank?
      end 
    end

    def claims
      _claims = {}
      _claims[:exp] = token_lifetime if verify_lifetime?
      _claims[:aud] = token_audience if verify_audience?
      _claims
    end

    def token_lifetime
      Knock.token_lifetime.from_now.to_i if verify_lifetime?
    end

    def verify_lifetime?
      !Knock.token_lifetime.nil?
    end

    def verify_claims(client_key)
      {
        aud: token_audience(client_key),
        verify_aud: verify_audience?,
        verify_expiration: verify_lifetime?
      }
    end

    def token_audience(client_key = 0)
      return unless auds = token_audiences
      auds[client_key] or raise InvalidClientKeyError
    end

    def token_audiences
      aud_or_auds = Knock.token_audience
      aud_or_auds = aud_or_auds.call if aud_or_auds.respond_to? :call

      case aud_or_auds
      when Hash
        aud_or_auds
      when Array
        Hash[aud_or_auds.map.with_index{|aud, i| [i, aud] }]
      else
        { 0 => aud_or_auds } unless aud_or_auds.blank?
      end
    end

    def verify_audience?
      token_audiences.present?
    end
  end
end
