require 'jwt'

module Knock
  class AuthToken
    attr_reader :token
    attr_reader :payload

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
        Knock.token_signature_algorithm
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
    def secret_key
      Knock.token_secret_signature_key.call
    end

    def decode_keys
      case key_or_keys = Knock.token_public_key || secret_key
      when Hash
        key_or_keys
      when Array
        Hash[key_or_keys.map.with_index{|key, i| [i, key] }]
      else
        {0 => key_or_keys}
      end
    end

    def options(client_key)
      verify_claims(client_key).merge({
        algorithm: Knock.token_signature_algorithm
      })
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

      auds[client_key] ||
        case auds
        when Hash then
          (auds.to_a[client_key] || [])[1]
        end
    end

    def token_audiences
      verify_audience? &&
        case aud_or_auds = Knock.token_audience.call
        when Array, Hash then aud_or_auds
        else [aud_or_auds]
        end
    end

    def verify_audience?
      Knock.token_audience.present?
    end
  end
end
