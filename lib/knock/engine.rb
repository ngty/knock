module Knock
  class Engine < ::Rails::Engine

    if ::Rails.const_defined? 'Generators'
      config.eager_load_paths += Dir["#{config.root}/lib/**/"]
    else
      require_relative './authenticable'
    end

    isolate_namespace Knock
  end
end
