#!/bin/ruby
require 'net/http'

google = URI('https://www.google.com')
resp = Net::HTTP.get(google)
