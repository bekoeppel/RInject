#!/usr/bin/ruby
# RInject.rb: RInject is a tool for automated testing of web applications and services. It can be used to test HTTP(S) interfaces for service-level monitoring. Compared to WebInject, RInject has a more powerful verification- and parsing-engine.
#   
#   *Author*:
#     Benedikt Koeppel
#     http://muasch.ch
#     mailto:be.public@gmail.com
#
#
#   *Licence*:
#     RInject: automated testing of web applications and services
#     Copyright (C) 2008 Benedikt A. Koeppel
#     This program is free software; you can redistribute it and/or modify it
#     under the terms of the GNU General Public License as published by the
#     Free Software Foundation; either version 3 of the License, or (at your
#     option) any later version.
#     This program is distributed in the hope that it will be useful, but
#     WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
#     Public License for more details.
#     You should have received a copy of the GNU General Public License along
#     with this program; if not, see <http://www.gnu.org/licenses/>. 
#     
#
#   *Usage*:
#   +rinject.rb [options]+
#     -c --config CONFIG: Specify config-file
#     -o --output OUTPUT: Specify output-location
#     -C --cases CASES: From where to load testcases
#     -h --help: Help
#   
#     RInject reads all testcases from the file, specified with -C or --cases
#  
#     Syntax for XML-File:
#     <testcases repeat="1">
#             <!-- +comment+ -->
#             <!-- basic schema of XML file -->
#             <case id="+id+" sleep="+seconds+" log="+error|all|request|response|none+">
#                     <description>+description+</description>
#                     <error>+error message+</error>
#                     <request method="+get|post+" url="+url+">
#                             <post type="+enctype+">
#                                     <postarg name="+name1+" value="+value1+" />
#                                     <postarg name="+nameN+" value="+valueN+" />
#                             </post>
#                             <header name="+header-name1+" value="+header-value1+" />
#                             <header name="+header-nameN+" value="+header-valueN+" />
#                             <httpauth username="+username+" password="+password"+ />
#                     </request>
#                     <response>
#                             <verify name="+verification-name1+" error="+errormessage1+" exp="+regular expression1+" type="+positive|negative+" />
#                             <verify name="+verification-nameN+" error="+errormessageN+" exp="+regular expressionN+" type="+positive|negative+" />
#                             <parse name="+parse-variable-name1+" exp="+regular expression1+" escape="+false|true+" default="+default-value1+" />
#                             <parse name="+parse-variable-nameN+" exp="+regular expressionN+" escape="+false|true+" default="+default-valueN+" />
#                     </response>
#             </case>
#  
#             <!-- two examples -->
#             <!-- example 1:
#                 - send POST-data to http://example.net/login.php with two additional headers
#                 - verify that responsecode is 200
#                 - verify that "Welcome Mr." or "Welcome Mrs." is in the source of the website
#                 - verify that "Failed to connect to" is *not* in the source of the website
#                 - read what's after "Welcome Mr." or "Welcome Mrs." in between to "!" and save this string as ${Username}
#                 -->
#             <case id="1" sleep="0" log="error">
#                     <description>POST Login to http://example.net/login.php</description>
#                     <error>POST Login failed!</error>
#                     <request method="post" url="http://example.net/login.php">
#                             <post type="application/x-www-form-urlencoded">
#                                     <postarg name="username" value="rinject" />
#                                     <postarg name="password" value="PW01234:" />
#                                     <postarg name="submit" value="true" />
#                             </post>
#                             <header name="User-Agent" value="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)" />
#                             <header name="Referer" value="http://example.net/index.php" />
#                     </request>
#                     <response>
#                             <verify name="HTTP responsecode" error="HTTP code 200 expected" exp="HTTP\/[\d]\.[\d] 200" type="positive" />
#                             <verify name="Successfully logged in" error="Welcome-String not found" exp="Welcome (Mr\.|Mrs\.)" type="positive" />
#                             <verify name="Database is not working" error="DB is not working" exp="Failed to connect to" type="negative" />
#                             <parse name="Username" exp="Welcome (Mr\.|Mrs\.) (.*?)!" escape="false" default="" />
#                     </response>
#             </case>
#             
#             <!-- example 2:
#                 - send GET-request to http://example.net/users/${Username} where ${Username} is the variable from case 1
#                 - verify that responsecode is 200
#                 - verify that "Userinformation for ${Username}" is in the source of the website
#                 -->
#             <case id="2" sleep="0" log="error">
#                     <description>View user details</description>
#                     <error>User details can't be displayed</error>
#                     <request method="get" url="http://example.net/users/${Username}" />
#                     <response>
#                             <verify name="HTTP responsecode" error="HTTP code 200 expected" exp="HTTP\/[\d]\.[\d] 200" type="positive" />
#                             <verify name="Information for ${Username}" error="No information about ${Username} displayed" exp="Userinformation for ${Username}" type="positive" />
#                     </response>
#             </case> 
#     </testcases>
#
#     Running +./rinject.rb -C testcases.xml+ puts out the status in Nagios plugin format of all cases as last line
#     run +./rinject.rb [options] | tail -n 1+ to get only the Nagios output
#
#
#   *TODO*:
# 
#     extend nagios-output:
#       - url of the first failed case
#       - error-text of the first failed verification (of this first case), if any verification failed (else: no output)
# 
#     timeout-option for commandline: realization: require 'timeout'; Timeout.timeout(seconds) do <block> end => timeout for everything together and timeout for each case separately
#       kind of:
#       >> begin
#       >>   Timeout.timeout(10) do
#       >>   sleep(11)
#       >> end
#       >>   rescue Timeout::Error
#       >> puts "timed out..."
#       >> end
#       total value is specified by -t TIMEOUT (or should this go to the XML-file in the <testcases...>?)
#       timeout for each case is specified in XML-file in <request... timeout="...">
#       a timeout of 0 should be interpreted as timeout Infinity
#       
# 
#     put _(...) and fail(...) into a lambda
# 
#     class XMLTag
#       initialize reads XML-object and gives access to all attributes of this xml-object
#       - is there a method in REXML to read *all* attributes (as hash or so?)
#       - probably overload [] operator? access to attributes via object['attribute-name']
#       - how could access to childs be provided? by object.child-name ?
# 
#     class Case could inherit from XML-class
# 
#     class Injector
#       initialize reads an xml-object case and executes this case
# 
#     more powerful cookie-class and a CookieContainer class
#       must respect all cookie-related attributes such as domain and path
# 
#     better error messages, if there are invalid XML-attributes in the config file
#
#     error handling for invalid URIs (URI::InvalidURIError) and when a site cannot be requested (SocketError)
#     
#     automated generation of flowcharts (dot? => external developer)
#       add parent tag 'host' for case. attributes description, url, host => grey box
#       extract from case: description, names of verifications and parsing => orange box
#       add key at the bottom (Server X... and description what Nagios/GW does)
#       => add link to all those flowcharts to nagios alert email
#       => add link to acknowledge an error to nagios alert email?
#



require 'rexml/document'
require 'optparse'
require 'net/http'
require 'net/https'
require 'uri'
require 'logger'
require 'base64'

# helper for Infinity
Infinity = 1/0.0

# Cookie-Container to store cookies, and retrive them for the next HTTP-request
class Cookies
  def initialize
    @cookies = {}
  end

  # adds cookie to container
  def add(name, value)
    @cookies[name] = value
    $log.debug("Cookie added: #{name}=#{value}")
  end

  # parses a Set-Cookie-string from HTTP Response Header and adds this cookie
  def parse(string)
    # split string to array, where Regexp matches
    return if string.nil?
    string.split(/,(?=[^;,]*=)|,$/).collect do |c|
      # split cookie name/value from parameters and then split name/value-pair into name and value
      name, value = c.split(/;/)[0].split(/=/,2) #/
      self.add(name,value)
    end
  end

  # returns string to use with {Cookie => ... } for HTTP request
  def to_header
    header_cookies = ""
    @cookies.each do |name, value|
      header_cookies += "#{name}=#{value}; "
    end
    return header_cookies
  end
  
  # deletes all cookies
  def clean!
    @cookies = {}
  end
end

# Verificationfailure
class VerificationFailure
  attr_reader :fid, :caseerror
  def initialize(fid, verificationerror, caseerror, expression, type)
    @fid=fid.to_i
    @error=verificationerror
    @caseerror=caseerror
    @expression=expression
    @type=type
  end
  
  def to_s
    return "Case ID #{@fid}: #{@type} verification /#{@expression}/ failed. #{@error}"
  end
end

# Casefailures
class CaseFailure
  attr_reader :fid, :error
  def initialize(fid, caseerror)
    @fid=fid.to_i
    @error=caseerror
  end
  
  def to_s
    return "Case ID #{@fid} failed! #{@error}"
  end
end

# Failure-Container
class FailureContainer
  def initialize
    @verification_failures = []
    @case_failures = []
  end
  
  def to_s
    return_msg=""
    if @verification_failures.size==0 and @case_failures.size==0
      return "All verifications passed."
    elsif @verification_failures.size==0
      # no verification_failures, but case_failures
      @case_failures.each do |cf|
        return_msg += cf.to_s + "\n"
      end
      return return_msg.chomp("\n")
    else
      # verification_failures
      @case_failures.each do |cf|
        @verification_failures.each do |vf|
          # if this verification_failure belongs to this case_failure
          if cf.fid == vf.fid
            return_msg += vf.to_s + "\n"
          end
        end
        return_msg += cf.to_s + "\n"
      end
      return return_msg.chomp("\n")
    end
  end
  
  # directly loggs all failures
  def to_log_warn(logger)
    if @verification_failures.size==0 and @case_failures.size==0
      # nothing to do, because no failure
    elsif @verification_failures.size==0
      # no verification_failures, but case_failures
      @case_failures.each do |cf|
        logger.warn(cf.to_s)
      end
    else
      # verification_failures
      @case_failures.each do |cf|
        @verification_failures.each do |vf|
          # if this verification_failure belongs to this case_failure
          if cf.fid == vf.fid
            logger.warn(vf.to_s)
          end
        end
        logger.warn(cf.to_s)
      end
    end
  end
  
  def first_to_s
    if @case_failures.size==0
      return "All verifications passed."
    else
      return @case_failures[0].to_s
    end
  end
  
  def add(vf)
    @verification_failures.push(vf)
    if not self.has_case(vf.fid)
      @case_failures.push(CaseFailure.new(vf.fid, vf.caseerror))
    end
  end
  
  def add_case(cf)
    if not self.has_case(cf.fid)
      @case_failures.push(cf)
    end
  end
  
  def count
    return @verification_failures.size
  end
  
  def count_cases
    return @case_failures.size
  end
  
  # check if Container already has a CaseFailure with Case-ID 'fid'
  def has_case(fid)
    @case_failures.each do |cf|
      if cf.fid == fid
        return true
      end
    end
    return false
  end
end




# searches through string and replaces all found variables
# a variable within a string is marked as ${name}
def _(string)
  if string.nil?
    return ""
  end
  @variables.each do |name, value|
    string.gsub!(/\$\{#{name}\}/,value)
  end
  return string
end


# creates a failure and adds this to failure-container
def fail(id, verificationerror, caseerror, expression, type)
  @failures.add(VerificationFailure.new(id,verificationerror, caseerror,expression,type))
end

# standard command line arguments
options = {
  "config" => "config.xml",
  "output" => "",
  "nooutput" => false,
  "testcase" => "",
  "repeat" => 0,
  "verbose" => false,
  "veryverbose" => false,
  "timeout" => Infinity,
  "graph" => false,
  "timer" => false
}

# parser for command line arguments
opts = OptionParser.new do |opts|
  opts.banner = "Usage: rinject.rb [options]"
  
  opts.on("-o", "--output OUTPUT", "Specify output-location") do |o|
    options["output"] = o
  end

  opts.on("-C", "--cases CASES", "Testcases") do |C|
    options["testcase"] = C
  end
  
  opts.on("-t", "--timeout TIMEOUT", "Timeout") do |t|
    options["timeout"] = t.to_i
  end

  opts.on("-v", "Verbose") do |v|
    # if called verbose more than once, set veryverbose to true
    if options["verbose"]
      options["veryverbose"]=true
    else
      options["verbose"] = true
    end
  end
  
  opts.on("-g", "Plot Graph") do |g|
    options ["graph"] = g
  end

  opts.on("-h", "--help", "This help.") do
    puts opts
    exit
  end
  
  opts.on("-T", "--timer", "Run two timers and reset it when configured") do |T|
    options["timer"] = T
  end
end

# parse command line options
opts.parse!( ARGV )

# global store for all parsed variables
@variable = {}

# global store for all failures
@failures = FailureContainer.new()

# Data-logger
# TODO: suppress all puts, if option -v (or -vv -vvv) isn't set
# TODO: use attribute log of case
if options["output"].downcase == "stdout"
  $log = Logger.new(STDOUT)
elsif options["output"] != ""
    $log = Logger.new(options["output"])
else
    $log = Logger.new("rinject.log")
end

$log.level = Logger::WARN
$log.level = Logger::INFO if options["verbose"]
$log.level = Logger::DEBUG if options["veryverbose"]

# load file as XML
# TODO: check XML-file (schema) before using it
if not options["testcase"] == ""
  file = File.new(options["testcase"])
else
  puts "RInject CRITICAL - no config file specified."
  exit 0
end
doc = REXML::Document.new file

# fetch cases and sort them by attribute id (id as integer, not as string)
cases = doc.elements.to_a("testcases/case")
cases.sort! { |a,b| a.attributes['id'].to_i <=> b.attributes['id'].to_i }

# read how many times the whole testcase should be performed
options["repeat"] = (doc.root.attributes['repeat'] or 1).to_i

# capture time before start
starttime = Time.now.to_f

# we want only to see the graph
if options["graph"] 
 
  description = "# Service #{doc.root.attributes['service']}, Host #{doc.root.attributes['host']}"
  header = "graph         { flow: south; }
  node.start    { shape: rounded; fill: #0000FFff; }
  node.question { shape: diamond; fill: #ffff8a; }
  node.action   { shape: rounded; fill: #8bef91; }"  
  header = "graph         { flow: south; }
  node.start    { shape: rounded; fill: #0000FFff; }
  node.question { shape: diamond; fill: #ffff8a; }
  node.action   { shape: rounded; fill: #8bef91; }"  
  start = "[ RInject Start ] {class: start; }"
  nodes=[]
  errors=[]
  ending = "[ RInject OK ] {class: start; }"
  
  # for each case # this is kind of ugly, but i need to access the (i+1)-th element
  (0..(cases.length-1)).each do |i|
    node = "[ Case #{i+1} #{cases[i].elements.to_a('description')[0].text.strip}\n"
    node.gsub!(/.{30}/, '\0\n')
    cases[i].elements.each('response/verify') do |v|
      # add verification description
      #nodeadd = "\n- #{v.attributes['name']} "
      nodeadd = "\\n"      

      # add "!" if negative verification
      if v.attributes['type']=="negative"
        nodeadd += "!"
      end
      
      # add expression and newline
      nodeadd += "- #{v.attributes['exp'].gsub('[', '\\[').gsub(']', '\\]')}\n"
      nodeadd.gsub!(/.{30}/, '\0\n')
      node += nodeadd
    end
    urlstring = "\\n(#{cases[i].elements.to_a('request')[0].attributes["url"]})"
    node += urlstring.gsub(/.{30}/, '\0\n')
    node += "] { class: question; }\n"
    node.gsub!(/\]\\n/,']')
    nodes.push(node)

    # add error node
    error = "[Error #{i+1}: #{cases[i].elements.to_a('error')[0].text.strip}]"
    error.gsub!(/.{30}/, '\0\n')
    error.gsub!(/\]\\n/,']')
    errors.push(error)
  end
  
  # output
  puts header
  puts description
  puts header
  puts start
  (0..(cases.length-1)).each do |i|
    puts " -- OK --> #{nodes[i]}"
    puts " -- ERROR --> #{errors[i]}"
    puts ""
    puts "#{nodes[i]}"
  end
  puts " -- OK --> #{ending}"
  Process.exit
end

# repeat testcase options["repeat"] times
options["repeat"].times do
  
  # for each run, get clean parsed variables and cookies
  @variables = {}
  cookies = Cookies.new()
  
  # process each testcase
  cases.each do |c|
  
    # if -T or --timer was specified and <timer>restart</timer> is set, restart the whole-in-one timer
    if options["timer"]
      if not c.elements.to_a('timer').nil? and not c.elements.to_a('timer')[0].nil?
        
        runningtime = ((Time.now.to_f-starttime)*1000.0).round/1000.0
        $log.info("Restarting timer now. This set of testcases took #{runningtime} seconds up to here.|time=#{runningtime};#{Time.now};#{Time.now.to_f};")
        
        # if <timer>quietrestart</timer>, just restart timer without output (only logging). else, show output
        if c.elements.to_a('timer')[0].text.strip != "quietrestart"
          puts "Restarting timer now. This set of testcases took #{runningtime} seconds up to here.|time=#{runningtime};#{Time.now};#{Time.now.to_f};"
        end
      
        starttime=Time.now.to_f
      end
    end
    
    # no failures for this case yet
    case_failures = false

    # fetch request and url
    request = c.elements.to_a('request')[0]
    url = _(request.attributes['url'])

    # log info about this case
    $log.info("Case #{c.attributes['id']}: #{_(c.elements.to_a('description')[0].text.strip)} (#{url})")
        
    # prepare request
    begin
      url_parse = URI.parse(url)
    rescue
      $log.warn("Error: Case #{c.attributes['id']}: #{_(c.elements.to_a('description')[0].text.strip)} (Request failed)")
      @failures.add_case( CaseFailure.new( c.attributes['id'].to_i, _(c.elements.to_a('error')[0].text.strip)+" (Request error) \n #{$!.message} \n #{$!.backtrace.join('\n')}" ) )
      $log.info("+"*80)
      next      
    end
    host = url_parse.host
    port = url_parse.port
    if url_parse.query!="" and url_parse.query!= nil
      path = "#{url_parse.path}?#{url_parse.query}"
    else
      path = "#{url_parse.path}"
    end
    path = "/" if path==""

    # set ssl to true, if url_parse.scheme is "https"
    ssl = (url_parse.scheme=="https")

    method = request.attributes['method'].downcase
    method="get" unless method=="post"
    
    # parse headers and add cookies
    header = {}
    # NOTE: if you want to send another User-Agent, specify <header name="User-Agent" value="..."> within <request>
    # NOTE: if you want to suppress sending cookies, specify <header name="Cookie" value=""> within <request>
    header["User-Agent"] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0)"
    header["Cookie"] = cookies.to_header
    c.elements.each('request/header') do |h|
      header[_(h.attributes["name"])] = _(h.attributes["value"])
    end
    
    # HTTP autorization (base64 encoded)
    httpauth = c.elements.to_a('request/httpauth')
    if not httpauth.nil? and not httpauth==[]
      username = httpauth[0].attributes['username']
      password = httpauth[0].attributes['password']
      header["Authorization"] = "Basic " + Base64.encode64("#{username}:#{password}").chomp("\n")
    end

    # generate POST arguments
    # NOTE: posttype is set to "application/x-www-form-urlencoded", if not specified in XML-file
    if method=="post"
      posttype = ""
      posttype = (_(c.elements.to_a('request/post')[0].attributes['type'])).strip
      posttype = "application/x-www-form-urlencoded" if posttype="" or posttype==nil
      header["Content-Type"] = posttype
      
      postargs=""
      c.elements.each('request/post/postarg') do |p|
        postargs += "#{_(p.attributes['name'])}=#{_(p.attributes['value'])}&"
      end
      postargs.chomp!("&")  # remove last &
    end
    
    # additional info about this request
    $log.debug("Request URL #{url} by method #{method} (SSL: #{ssl}, Port #{port}, Host #{host}, Path #{path})
             Additional Header: #{header.inspect}")
    $log.debug("Post: #{postargs} (#{posttype})") if method=="post"

    
    # send request
    # http-controller
    if ssl
      http = Net::HTTP.new(host, port)
      http.use_ssl = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    else
      http = Net::HTTP.new(host, port)
      http.use_ssl = false
    end
    
    # send request and fetch body and header
    # if a problem occurs, continue with next request and put a message for failed cases
    response = ""
    begin
      request_starttime = Time.now
      Timeout.timeout(options["timeout"]) do
        if method=="get"
          response = http.get(path, header)
        else
          response = http.post(path, postargs, header)
        end
      end
    rescue Timeout::Error
      $log.warn("Error: Case #{c.attributes['id']}: #{_(c.elements.to_a('description')[0].text.strip)} (Timed out)")
      @failures.add_case( CaseFailure.new( c.attributes['id'].to_i, _(c.elements.to_a('error')[0].text.strip)+" (Request error, #{url} timed out) \n #{$!.message} \n #{$!.backtrace.join('\n')}" ) )
      $log.info("+"*80)
      next
    rescue
      $log.warn("Error: Case #{c.attributes['id']}: #{_(c.elements.to_a('description')[0].text.strip)} (Request failed)")
      @failures.add_case( CaseFailure.new( c.attributes['id'].to_i, _(c.elements.to_a('error')[0].text.strip)+" (Request error) \n #{$!.message} \n #{$!.backtrace.join('\n')}" ) )
      $log.info("+"*80)
      next
    end

    # read response
    status = "HTTP/#{response.http_version} #{response.code} #{response.message}"
    body = response.body
    head = ""
    response.each_capitalized{ |key, value| head += "#{key}: #{value}\n" }
    cookies.parse(response['Set-Cookie'])
    request_totaltime = Time.now - request_starttime
    $log.info("Request processed within #{request_totaltime} seconds.")
    $log.debug("#{status}\n#{head}\n#{body}")


    # verifications
    # NOTE: Status-Code verifications can be done with
    #       <verify name="HTTP-Code" error="HTTP Code 200 expected" exp="HTTP\/[\d]\.[\d] 200" type="positive" />
    c.elements.each('response/verify') do |v|
      
      # get data to verify
      type = (v.attributes['type'] or "positive")
      name = v.attributes['name']
      error = (v.attributes['error'] or name)
      expression = v.attributes['exp']
      
      # verification
      verification = "#{status}\n#{head}\n#{body}".match(/#{expression}/)
      
      # check for errors:
      # error occured, when verification must be positive, but is negative (or vice versa)
      if (type=="positive" and !verification) or (type=="negative" and verification)
        $log.warn("Verification /#{expression}/ failed! #{error}")
        case_failures = true
        fail(c.attributes['id'], error, _(c.elements.to_a('error')[0].text.strip), expression, type)
      else
        $log.info("Verification /#{expression}/ #{type} matched!")
      end
    end

    # parse response to store variables (<parse />)
    c.elements.each('response/parse') do |p|
      
      # get data to parse
      name = p.attributes['name']
      expression = p.attributes['exp']
      escape = p.attributes['escape'].downcase
      default = (p.attributes['default'] or "")
      # set escape to true, if escape=="true", else set it to false
      escape = (escape=="true")
      
      # read head and body and look for the expression
      parsed = "#{status}\n#{head}\n#{body}".match(/#{expression}/m)
      if !parsed
        $log.warn("Expression /#{expression}/ could not be found in response. Default value saved: ${#{name}}=\"#{default}\"")
        @variables[name] = default
      else
        # if string found, save to hash (with escape, if this is specified)
        if escape
          value = URI.escape(parsed[1], Regexp.new("[^#{URI::PATTERN::UNRESERVED}]"))
        else
          value = parsed[1]
        end
        @variables[name] = value
        $log.info("Expression /#{expression}/ found. Result: #{parsed[1]} stored as #{name}")

      end
    end
   
    # print errormessage, if failures occured for this case
    if case_failures
      $log.warn("Error: Case #{c.attributes['id']}: #{_(c.elements.to_a('description')[0].text.strip)}")
      @failures.add_case(CaseFailure.new(c.attributes['id'].to_i, _(c.elements.to_a('error')[0].text.strip)))
    end
    
    # wait attributes['sleep'] milliseconds before continuing
    sleep( (c.attributes['sleep'] or 0).to_i )

    # print some separators after each case
    $log.info("+"*80)
  end
    
  # print some separators after each run
  $log.info("-"*80)
end

# capture time after ending tests
endtime = Time.now.to_f
runningtime = ((endtime-starttime)*1000.0).round/1000.0

# log all errors
@failures.to_log_warn($log)

# print nagios output as last line
# NOTE: with ./roinject.rb | tail -n 1 you can get only the Nagios-Output
if @failures.count_cases == 0
  $log.info("RInject OK - All verifications passed. |time=#{runningtime};#{Time.now};#{Time.now.to_f};")
  puts "RInject OK - All verifications passed. |time=#{runningtime};#{Time.now};#{Time.now.to_f};"
  exit 0
else
  $log.warn("RInject CRITICAL - #{@failures.first_to_s} |time=#{runningtime};#{Time.now};#{Time.now.to_f};")
  puts "RInject CRITICAL - #{@failures.first_to_s} |time=#{runningtime};#{Time.now};#{Time.now.to_f};"
  exit 2
end
