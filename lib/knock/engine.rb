module Knock
  class Engine < ::Rails::Engine

    def self.require_all!
      config.eager_load_paths += Dir["#{config.root}/lib/**/"]
    end

    def self.require_default!
      Dir["#{config.root}/lib/knock/**/*.rb"].
        each{|f| require f unless f == __FILE__ }
    end

    %w(production staging).include?(::Rails.env) ?
      require_default! : require_all!

    isolate_namespace Knock
  end
end
