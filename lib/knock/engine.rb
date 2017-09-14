module Knock
  class Engine < ::Rails::Engine

    if ::Rails.const_defined? 'Generators'
      config.eager_load_paths += Dir["#{config.root}/lib/**/"]
    else
      Dir["#{config.root}/lib/knock/**/*.rb"].each{|f| require f }
    end

    isolate_namespace Knock
  end
end
