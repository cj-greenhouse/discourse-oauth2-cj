## discourse-oauth2-cj

This plugin is based on the generic oauth2 plugin, with customizations so that it understand's CJ's use of
JWTs

### How to run tests

Make sure the plugin has been installed, then from the discourse directory run:

    LOAD_PLUGINS=1 bundle exec rspec plugins/discourse-oauth2-basic/spec/plugin_spec.rb

