# Encoding UTF-8

require 'vault'
require 'aws-sdk-core'

module VaultCookbook
  module Helper
    class << self
      # Configuring Vault
      def config(address)
        Vault.address = address
        Vault.ssl_verify = false
      end

      # Approle Auth Method
      def approle(approleid, appsecretid, path, secret_name)
        Vault.with_retires(Vault::HTTPConnectionError, Vault::HTTPError, Vault::HTTPClientError, attempts: 3) do |attempts, error|
          Chef::log.error "Received exception #{error.class} from Vault while authenticating - attempt #{attempts}"
          # Parsing the client token
          Vault.token = Vault.auth.approle(approleid, appsecretid).auth.client_token
          return Vault.logical.read(path).data[:"#{secret_name}"]
        end
      end

      # IAM Auth Method
      def IAM(vault_endpoint, vault_role, path, secret_name)
        Vault.with_retires(Vault::HTTPConnectionError, Vault::HTTPError, Vault::HTTPClientError, attempts: 3) do |attempts, error|
          Chef::log.error "Received exception #{error.class} from Vault while authenticating - attempt #{attempts}"
          Vault.auth.aws_iam(vault_role, AWS::InstnaceProfileCredentials.new, vault_endpoint)
          return Vault.logical.read(path).data[:"#{secret_name}"]
        end
      end
    end
  end
end
