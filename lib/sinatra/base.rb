# external dependencies
require 'rack'
require 'tilt'
require 'rack/protection'

# stdlib dependencies
require 'thread'
require 'time'
require 'uri'

# other files we need
require 'sinatra/show_exceptions'
require 'sinatra/ext'
require 'sinatra/version'

module Sinatra
  # The request object. See Rack::Request for more info:
  # http://rubydoc.info/github/rack/rack/master/Rack/Request

  # Sinatra 包装了Rack的Reqeust
  class Request < Rack::Request
    HEADER_PARAM = /\s*[\w.]+=(?:[\w.]+|"(?:[^"\\]|\\.)*")?\s*/
    HEADER_VALUE_WITH_PARAMS = /(?:(?:\w+|\*)\/(?:\w+(?:\.|\-|\+)?|\*)*)\s*(?:;#{HEADER_PARAM})*/

    # Returns an array of acceptable media types for the response

    # 扫描 HTTP_ACCEPT 中的值，然后将每个accept类型封装成 AcceptEntry 的一个实例
    # 返回 AcceptEntry 的实例数组
    def accept
      @env['sinatra.accept'] ||= begin
        if @env.include? 'HTTP_ACCEPT' and @env['HTTP_ACCEPT'].to_s != ''
          @env['HTTP_ACCEPT'].to_s.scan(HEADER_VALUE_WITH_PARAMS).
            map! { |e| AcceptEntry.new(e) }.sort
        else
          [AcceptEntry.new('*/*')]
        end
      end
    end

    # 如果可以 accept 这个类型，返回true， 否则返回false
    def accept?(type)
      preferred_type(type).to_s.include?(type)
    end

    # 通过调用 accept 获得 AcceptEntry 实例数组
    # 然后和 types 比对，找到
    def preferred_type(*types)
      accepts = accept # just evaluate once
      return accepts.first if types.empty?
      types.flatten!
      return types.first if accepts.empty?
      accepts.detect do |pattern|
        type = types.detect { |t| File.fnmatch(pattern, t) }
        return type if type
      end
    end

    alias secure? ssl?

    # 参考 http://stackoverflow.com/questions/17411391/whats-the-variable-http-x-forwarded-host-in-the-env-hash-in-middleware
    # 当 用户和服务器之间有代理，这个option就会被设置
    def forwarded?
      @env.include? "HTTP_X_FORWARDED_HOST"
    end

    def safe?
      get? or head? or options? or trace?
    end

    def idempotent?
      safe? or put? or delete? or link? or unlink?
    end

    def link?
      request_method == "LINK"
    end

    def unlink?
      request_method == "UNLINK"
    end

    private
    # 用来封装 Accept 类型的class
    class AcceptEntry
      attr_accessor :params
      attr_reader :entry

      def initialize(entry)
        params = entry.scan(HEADER_PARAM).map! do |s|
          key, value = s.strip.split('=', 2)
          value = value[1..-2].gsub(/\\(.)/, '\1') if value.start_with?('"')
          [key, value]
        end

        #就是传进来的entry 例如："application/xml;q=0.9"
        @entry  = entry
        # 去掉了q之后的类型 "application/xml"
        @type   = entry[/[^;]+/].delete(' ')
        @params = Hash[params]
        # q是权重 0 到 1 之间，q越大，请求越倾向于获得 ;之前的类型
        # 例如在 accept: application/xml;q=0.9,image/webp,*/*;q=0.8
        # 这里的{1.0} 用到了ruby Hash#delete的一个技巧
        # 表示如果delete的元素不存在，那么执行block的内容作为默认值返回
        @q      = @params.delete('q') { 1.0 }.to_f
      end

      # 因为 priority 是数组，所以可以用 <=> 来比较
      def <=>(other)
        other.priority <=> self.priority
      end

      def priority
        # We sort in descending order; better matches should be higher.
        [ @q, -@type.count('*'), @params.size ]
      end

      def to_str
        @type
      end

      # 可以选择输出完整的AcceptEntry，或者仅仅type
      def to_s(full = false)
        full ? entry : to_str
      end

      def respond_to?(*args)
        super or to_str.respond_to?(*args)
      end

      # 小技巧： 这里是允许将AcceptEntry当做一个string来用
      def method_missing(*args, &block)
        to_str.send(*args, &block)
      end
    end
  end

  # The response object. See Rack::Response and Rack::Response::Helpers for
  # more info:
  # http://rubydoc.info/github/rack/rack/master/Rack/Response
  # http://rubydoc.info/github/rack/rack/master/Rack/Response/Helpers

  # 在 Rack::Response 基础上包装了一层
  class Response < Rack::Response

    # 没有 body 的请求方法
    # 204 No Content 很常用
    # 205 Reset Content 需要重置表单
    # 304 Not Modified 一般表示内容没有更新，可以使用缓存
    DROP_BODY_RESPONSES = [204, 205, 304]
    def initialize(*)
      super
      # 设置默认的 Content-Type 为 'text/html'
      headers['Content-Type'] ||= 'text/html'
    end

    def body=(value)
      # 这里的while是为了防止 body 中嵌套 Rack::Response
      value = value.body while Rack::Response === value

      # rack 的 response 是 [status code, header, body], body 是一个数组
      # 如果赋值的body是string，那么转换为 [body]
      @body = String === value ? [value.to_str] : value
    end

    def each
      block_given? ? super : enum_for(:each)
    end

    # 为response 处理 Content-Lenth
    # 如果没有body, 就调用 Rack::Response#close 方法
    # 否则 手动计算每个body中的长度总和 并设置为 Content-Length
    def finish
      result = body

      if drop_content_info?
        headers.delete "Content-Length"
        headers.delete "Content-Type"
      end

      if drop_body?
        close
        result = []
      end

      if calculate_content_length?
        # if some other code has already set Content-Length, don't muck with it
        # currently, this would be the static file-handler
        headers["Content-Length"] = body.inject(0) { |l, p| l + Rack::Utils.bytesize(p) }.to_s
      end

      [status.to_i, headers, result]
    end

    private

    def calculate_content_length?
      headers["Content-Type"] and not headers["Content-Length"] and Array === body
    end

    def drop_content_info?
      status.to_i / 100 == 1 or drop_body?
    end

    def drop_body?
      DROP_BODY_RESPONSES.include?(status.to_i)
    end
  end

  # 接着定义了两个 Rack 的 middleware ExtendedRack 和 CommonLogger

  # Some Rack handlers (Thin, Rainbows!) implement an extended body object protocol, however,
  # some middleware (namely Rack::Lint) will break it by not mirroring the methods in question.
  # This middleware will detect an extended body object and will make sure it reaches the
  # handler directly. We do this here, so our middleware and middleware set up by the app will
  # still be able to run.

  # todo 这个不是很看得懂
  class ExtendedRack < Struct.new(:app)
    def call(env)
      result, callback = app.call(env), env['async.callback']
      return result unless callback and async?(*result)
      after_response { callback.call result }
      setup_close(env, *result)
      throw :async
    end

    private

    def setup_close(env, status, headers, body)
      return unless body.respond_to? :close and env.include? 'async.close'
      env['async.close'].callback { body.close }
      env['async.close'].errback { body.close }
    end

    def after_response(&block)
      raise NotImplementedError, "only supports EventMachine at the moment" unless defined? EventMachine
      EventMachine.next_tick(&block)
    end

    def async?(status, headers, body)
      return true if status == -1
      body.respond_to? :callback and body.respond_to? :errback
    end
  end

  # Behaves exactly like Rack::CommonLogger with the notable exception that it does nothing,
  # if another CommonLogger is already in the middleware chain.

  # 这个middleware其实是为了保证，Sinatra::CommonLogger 只会有一个在middleware链上
  # 当重复的 Sinatra::CommonLogger 被引入，因为之前被引入过，所以env['sinatra.commonlogger'] 是true
  # 那么就会直接调用 @app.call(env) 从而跳过重复的 Sinatra::CommonLogger
  class CommonLogger < Rack::CommonLogger
    def call(env)
      env['sinatra.commonlogger'] ? @app.call(env) : super
    end

    # 往父类的 call 方法注入了 env['sinatra.commonlogger'] = true
    superclass.class_eval do
      alias call_without_check call unless method_defined? :call_without_check
      def call(env)
        env['sinatra.commonlogger'] = true
        call_without_check(env)
      end
    end
  end

  class NotFound < NameError #:nodoc:
    def http_status; 404 end
  end

  # 这个module 会被 Base include， 包含了一些实用的方法
  # Methods available to routes, before/after filters, and views.
  module Helpers
    # Set or retrieve the response status code.
     # 设置或者获得status
    def status(value = nil)
      response.status = value if value
      response.status
    end

    # Set or retrieve the response body. When a block is given,
    # evaluation is deferred until the body is read with #each.

    # 用来获取或者设置body
    # 设置的body可以是一个value值, 也可以是一个block
    def body(value = nil, &block)
      if block_given?
        # 如果是一个block，那么定义一个实例方法each
        # 当这个 body 被调用的时候，each方法也会被调用
        # 先用过调用call方法执行block的内容，然后将计算出来的值当做参数传给each的block
        def block.each; yield(call) end
        response.body = block
      elsif value
        # 对于没有body，或者body不能计算长度的请求，去掉 Content-Length
        headers.delete 'Content-Length' unless request.head? || value.is_a?(Rack::File) || value.is_a?(Stream)
        # 设置body
        response.body = value
      else
        # 获取body
        response.body
      end
    end

    # Halt processing and redirect to the URI provided.
    def redirect(uri, *args)
      # 303 是 http 1.1 的规范
      if env['HTTP_VERSION'] == 'HTTP/1.1' and env["REQUEST_METHOD"] != 'GET'
        status 303
      else
        # 302 是之前的规范
        status 302
      end

      # According to RFC 2616 section 14.30, "the field value consists of a
      # single absolute URI"
      #根据 RFC2616 302/303 类型的跳转应该是绝对跳转
      # 但是这里当 settings.absolute_redirects 被设置为false，会允许相对跳转
      # settings.prefixed_redirects 表示相对路径的时候，是否使用 script_name 作为前缀
      # 文档中有提到
      response['Location'] = uri(uri.to_s, settings.absolute_redirects?, settings.prefixed_redirects?)
      halt(*args)
    end

    # Generates the absolute URI for a given path in the app.
    # Takes Rack routers and reverse proxies into account.
    def uri(addr = nil, absolute = true, add_script_name = true)
      return addr if addr =~ /\A[A-z][A-z0-9\+\.\-]*:/、
      # 这里是一个trick，设置uri为host的数组，然后更改host
      # 这里其实就是修改了uri的值
      uri = [host = ""]
      # 如果是absolute，加上http/https
      if absolute
        host << "http#{'s' if request.secure?}://"
        if request.forwarded? or request.port != (request.secure? ? 443 : 80)
          # 如果不是 80 或 443， host加上端口
          host << request.host_with_port
        else
          host << request.host
        end
      end
      # 加上 script_name
      uri << request.script_name.to_s if add_script_name
      # 如果 addr 是空，那么加上 path_info
      # 一个url是由 script_name + path_info
      uri << (addr ? addr : request.path_info).to_s
      File.join uri
    end

    alias url uri
    alias to uri

    # Halt processing and return the error status provided.
    # 报错的时候，会halt并扔出500
    def error(code, body = nil)
      code, body    = 500, code.to_str if code.respond_to? :to_str
      response.body = body unless body.nil?
      halt code
    end

    # Halt processing and return a 404 Not Found.
    def not_found(body = nil)
      error 404, body
    end

    # Set multiple response headers with Hash.
    def headers(hash = nil)
      response.headers.merge! hash if hash
      response.headers
    end

    # Access the underlying Rack session.
    def session
      request.session
    end

    # Access shared logger object.
    def logger
      request.logger
    end

    # Look up a media type by file extension in Rack's mime registry.
    def mime_type(type)
      Base.mime_type(type)
    end

    # Set the Content-Type of the response body given a media type or file
    # extension.
    # 获取或设置Content-Type
    def content_type(type = nil, params = {})
      # 获取 Content-Type
      return response['Content-Type'] unless type
      # 默认值依赖于template
      default = params.delete :default
      # 然后获得对应的 mime_type
      mime_type = mime_type(type) || default
      fail "Unknown media type: %p" % type if mime_type.nil?
      mime_type = mime_type.dup

      # Content-Type 需要 charset 参数 "Content-Type: text/html; charset=utf-8"
      # 这里设置charset
      unless params.include? :charset or settings.add_charset.all? { |p| not p === mime_type }
        params[:charset] = params.delete('charset') || settings.default_encoding
      end
      # 如果 mime_type 中含有 charset 了， 那么就从params中删除掉它
      params.delete :charset if mime_type.include? 'charset'

      # todo 不是很明白
      unless params.empty?
        mime_type << (mime_type.include?(';') ? ', ' : ';')
        mime_type << params.map do |key, val|
          val = val.inspect if val =~ /[";,]/
          "#{key}=#{val}"
        end.join(', ')
      end
      response['Content-Type'] = mime_type
    end

    # Set the Content-Disposition to "attachment" with the specified filename,
    # instructing the user agents to prompt to save.

    # 这个 api 告诉浏览器，这个response是要被保存的，而不是在浏览器打开
    def attachment(filename = nil, disposition = 'attachment')
      response['Content-Disposition'] = disposition.to_s
      if filename
        params = '; filename="%s"' % File.basename(filename)
        response['Content-Disposition'] << params

        # 从后缀名取content type
        ext = File.extname(filename)
        content_type(ext) unless response['Content-Type'] or ext.empty?
      end
    end

    # Use the contents of the file at +path+ as the response body.
    # 这个 api 返回文件的内容
    def send_file(path, opts = {})
      # 从 option 或者 后缀名中获取 Content-Type
      if opts[:type] or not response['Content-Type']
        content_type opts[:type] || File.extname(path), :default => 'application/octet-stream'
      end

      disposition = opts[:disposition]
      filename    = opts[:filename]
      disposition = 'attachment' if disposition.nil? and filename
      filename    = path         if filename.nil?
      attachment(filename, disposition) if disposition

      last_modified opts[:last_modified] if opts[:last_modified]

      file      = Rack::File.new nil
      file.path = path
      # 生成一个serve 文件的http 回复，处理了 304 和 http_range 的情况
      result    = file.serving env
      result[1].each { |k,v| headers[k] ||= v }
      headers['Content-Length'] = result[1]['Content-Length']
      opts[:status] &&= Integer(opts[:status])
      halt opts[:status] || result[0], result[2]
    rescue Errno::ENOENT
      not_found
    end

    # Class of the response body in case you use #stream.
    #
    # Three things really matter: The front and back block (back being the
    # block generating content, front the one sending it to the client) and
    # the scheduler, integrating with whatever concurrency feature the Rack
    # handler is using.
    #
    # Scheduler has to respond to defer and schedule.
    # 这个class 用来作为response 的 body
    # 同时也作为一个scheduler，响应 schedule 和 defer 方法
    # 作为Rack的body，必须响应 each 方法
    # front block 是由各个 http 服务器提供的，他们控制了如何将内容提供到客户端
    # back block 是用户传过来的代码块，告诉我们如何生成内容
    class Stream
      def self.schedule(*) yield end
      def self.defer(*)    yield end

      def initialize(scheduler = self.class, keep_open = false, &back)
        @back, @scheduler, @keep_open = back.to_proc, scheduler, keep_open
        @callbacks, @closed = [], false
      end

      def close
        return if closed?
        @closed = true
        @scheduler.schedule { @callbacks.each { |c| c.call }}
      end

      # 这个方法是被各个 http 服务器调用的
      # 调用了的时候，执行 back block，计算出要生成的内容
      # 而在执行back block的期间
      # back block 中的 << 会执行front block中的内容
      def each(&front)
        @front = front
        @scheduler.defer do
          begin
            # 这里执行back，会触发执行 << 方法（因为back里面有 out << content ）
            # front就被执行了，response的内容就被真正的写入了http body
            @back.call(self)
          rescue Exception => e
            @scheduler.schedule { raise e }
          end
          close unless @keep_open
        end
      end

      def <<(data)
        @scheduler.schedule { @front.call(data.to_s) }
        self
      end

      def callback(&block)
        return yield if closed?
        @callbacks << block
      end

      alias errback callback

      def closed?
        @closed
      end
    end

    # Allows to start sending data to the client even though later parts of
    # the response body have not yet been generated.
    #
    # The close parameter specifies whether Stream#close should be called
    # after the block has been executed. This is only relevant for evented
    # servers like Thin or Rainbows.
    def stream(keep_open = false)
      scheduler = env['async.callback'] ? EventMachine : Stream
      current   = @params.dup
      # 这里的 out 就是一个Stream的实例
      # 用with_params 可能是怕会污染 params
      body Stream.new(scheduler, keep_open) { |out| with_params(current) { yield(out) } }
    end

    # Specify response freshness policy for HTTP caches (Cache-Control header).
    # Any number of non-value directives (:public, :private, :no_cache,
    # :no_store, :must_revalidate, :proxy_revalidate) may be passed along with
    # a Hash of value directives (:max_age, :min_stale, :s_max_age).
    #
    #   cache_control :public, :must_revalidate, :max_age => 60
    #   => Cache-Control: public, must-revalidate, max-age=60
    #
    # See RFC 2616 / 14.9 for more on standard cache control directives:
    # http://tools.ietf.org/html/rfc2616#section-14.9.1

    # 如英文注释，这个 api 帮助设置 http Cache-Control 属性
    def cache_control(*values)
      # 因为hash的属性是最后一个，所以处理最后的hash属性
      if values.last.kind_of?(Hash)
        hash = values.pop
        # 去掉不需要设置的属性
        hash.reject! { |k,v| v == false }
        # 将一些不需要值但又值为true的属性添加到 values
        # 并且将其从 hash 中删除
        hash.reject! { |k,v| values << k if v == true }
      else
        hash = {}
      end

      # 将 `_` 替换为 `-`
      values.map! { |value| value.to_s.tr('_','-') }
      # 对于hash中其他的属性，转换成标准格式
      # 从 :max_age => 60 转换成 max-age=60
      hash.each do |key, value|
        key = key.to_s.tr('_', '-')
        value = value.to_i if key == "max-age"
        values << "#{key}=#{value}"
      end

      response['Cache-Control'] = values.join(', ') if values.any?
    end

    # Set the Expires header and Cache-Control/max-age directive. Amount
    # can be an integer number of seconds in the future or a Time object
    # indicating when the response should be considered "stale". The remaining
    # "values" arguments are passed to the #cache_control helper:
    #
    #   expires 500, :public, :must_revalidate
    #   => Cache-Control: public, must-revalidate, max-age=60
    #   => Expires: Mon, 08 Jun 2009 08:50:17 GMT
    #

    # 这个 api 其实包装了 cache_control 方法
    # 它将过期的相对时间转换成绝对时间，作为 Expires 的值
    # 然后将其他参数全部传给 cache_control 中去
    def expires(amount, *values)
      values << {} unless values.last.kind_of?(Hash)

      # time 是绝对时间 用来设置 Expires 时间
      # max_age 是相对时间，用来设置 Cache-Control
      if amount.is_a? Integer
        time    = Time.now + amount.to_i
        max_age = amount
      else
        time    = time_for amount
        max_age = time - Time.now
      end

      values.last.merge!(:max_age => max_age)
      cache_control(*values)

      # 必须 require 'time' 才能有 httpdate 方法
      response['Expires'] = time.httpdate
    end

    # Set the last modified time of the resource (HTTP 'Last-Modified' header)
    # and halt if conditional GET matches. The +time+ argument is a Time,
    # DateTime, or other object that responds to +to_time+.
    #
    # When the current request includes an 'If-Modified-Since' header that is
    # equal or later than the time specified, execution is immediately halted
    # with a '304 Not Modified' response.

    # If-Modified-Since 是发送请求时的http头部请求标签，服务器会把这个时间与服务器上实际文件的最后修改时间进行比较
    # 如果没有修改，则返回304 请求
    # Http 回复会有 Last-Modified 时间
    # 这个 api 用来设置 Last-Modified 的时间，同时也会做检查
    def last_modified(time)
      return unless time
      time = time_for time
      response['Last-Modified'] = time.httpdate
      # 如果这个请求需要 etag 缓存验证，那么就不根据 last_modified 的做时间验证
      return if env['HTTP_IF_NONE_MATCH']

      # 如果请求中带 If-Modified-Since 那么需要比较，然后可能回复304
      if status == 200 and env['HTTP_IF_MODIFIED_SINCE']
        # compare based on seconds since epoch
        since = Time.httpdate(env['HTTP_IF_MODIFIED_SINCE']).to_i
        halt 304 if since >= time.to_i
      end

      # todo 这块不理解，412 是先决条件不符合
      if (success? or status == 412) and env['HTTP_IF_UNMODIFIED_SINCE']
        # compare based on seconds since epoch
        since = Time.httpdate(env['HTTP_IF_UNMODIFIED_SINCE']).to_i
        halt 412 if since < time.to_i
      end
    rescue ArgumentError
    end

    # etag 分为强校验和弱校验
    # "123456789"    – 强校验
    # W/"123456789"  – 弱校验 前面带个W

    ETAG_KINDS = [:strong, :weak]
    # Set the response entity tag (HTTP 'ETag' header) and halt if conditional
    # GET matches. The +value+ argument is an identifier that uniquely
    # identifies the current version of the resource. The +kind+ argument
    # indicates whether the etag should be used as a :strong (default) or :weak
    # cache validator.
    #
    # When the current request includes an 'If-None-Match' header with a
    # matching etag, execution is immediately halted. If the request method is
    # GET or HEAD, a '304 Not Modified' response is sent.

    # etag 是服务器返回给客户端的
    # 客户端则是带上 If-Match 或者 If-None-Match
    # 这个方法用来设置etag 同时也会处理客户端传来的 If-Match 和 If-None-Match ( 为什么处理也在这个函数，你们自己想一下 :) )
    # 什么时候带 If-Match, 什么时候带 If-None-Match 是可以根据语义的
    # 例如，get head 请求带 If-None-Match。 语义是，如果资源和这个etag不符合，才给我资源
    # 而put patch 请求带 If-Match。语义是， 如果我要修改的资源还是原来的资源，那么就更新，否则 412
    def etag(value, options = {})
      # Before touching this code, please double check RFC 2616 14.24 and 14.26.
      options      = {:kind => options} unless Hash === options
      kind         = options[:kind] || :strong
      new_resource = options.fetch(:new_resource) { request.post? }

      # etag 校验只能是 strong 或者 weak
      unless ETAG_KINDS.include?(kind)
        raise ArgumentError, ":strong or :weak expected"
      end

      value = '"%s"' % value
      value = "W/#{value}" if kind == :weak
      response['ETag'] = value

      # 如果先决条件是不匹配
      if success? or status == 304
        # 如果 etag 匹配
        if etag_matches? env['HTTP_IF_NONE_MATCH'], new_resource
          # 如果是安全的请求，返回304
          # 否则，因为希望的是不匹配，但是这里却匹配了，返回412
          halt(request.safe? ? 304 : 412)
        end

        # 如果 先决条件是匹配，但这里 etag 不匹配， 那么返回412
        if env['HTTP_IF_MATCH']
          halt 412 unless etag_matches? env['HTTP_IF_MATCH'], new_resource
        end
      end
    end

    # Sugar for redirect (example:  redirect back)
    # 回到 referer
    def back
      request.referer
    end

    # whether or not the status is set to 1xx
    def informational?
      status.between? 100, 199
    end

    # whether or not the status is set to 2xx
    def success?
      status.between? 200, 299
    end

    # whether or not the status is set to 3xx
    def redirect?
      status.between? 300, 399
    end

    # whether or not the status is set to 4xx
    def client_error?
      status.between? 400, 499
    end

    # whether or not the status is set to 5xx
    def server_error?
      status.between? 500, 599
    end

    # whether or not the status is set to 404
    def not_found?
      status == 404
    end

    # Generates a Time object from the given value.
    # Used by #expires and #last_modified.
    # 将 value 转换成 time 的方法
    def time_for(value)
      if value.respond_to? :to_time
        value.to_time
      elsif value.is_a? Time
        value
      elsif value.respond_to? :new_offset
        # DateTime#to_time does the same on 1.9
        d = value.new_offset 0
        t = Time.utc d.year, d.mon, d.mday, d.hour, d.min, d.sec + d.sec_fraction
        t.getlocal
      elsif value.respond_to? :mday
        # Date#to_time does the same on 1.9
        Time.local(value.year, value.mon, value.mday)
      elsif value.is_a? Numeric
        Time.at value
      else
        Time.parse value.to_s
      end
    rescue ArgumentError => boom
      raise boom
    rescue Exception
      raise ArgumentError, "unable to convert #{value.inspect} to a Time object"
    end

    private

    # Helper method checking if a ETag value list includes the current ETag.
    # 检查和 etag 是和否匹配
    def etag_matches?(list, new_resource = request.post?)
      # 如果是 * 表示全部匹配
      # 那么对于不是new_resource 那么 etag 就是匹配的
      return !new_resource if list == '*'
       # 检查是否有任何一个 etag 匹配
      list.to_s.split(/\s*,\s*/).include? response['ETag']
    end

    # 让 temp_params 临时充当了 @params的位置执行block
    def with_params(temp_params)
      original, @params = @params, temp_params
      yield
    ensure
      @params = original if original
    end
  end

  private

  # Template rendering methods. Each method takes the name of a template
  # to render as a Symbol and returns a String with the rendered output,
  # as well as an optional hash with additional options.
  #
  # `template` is either the name or path of the template as symbol
  # (Use `:'subdir/myview'` for views in subdirectories), or a string
  # that will be rendered.
  #
  # Possible options are:
  #   :content_type   The content type to use, same arguments as content_type.
  #   :layout         If set to something falsy, no layout is rendered, otherwise
  #                   the specified layout is used (Ignored for `sass` and `less`)
  #   :layout_engine  Engine to use for rendering the layout.
  #   :locals         A hash with local variables that should be available
  #                   in the template
  #   :scope          If set, template is evaluate with the binding of the given
  #                   object rather than the application instance.
  #   :views          Views directory to use.
  module Templates
    module ContentTyped
      attr_accessor :content_type
    end

    def initialize
      super
      @default_layout = :layout
      @preferred_extension = nil
    end

    def erb(template, options = {}, locals = {}, &block)
      render(:erb, template, options, locals, &block)
    end

    def erubis(template, options = {}, locals = {})
      warn "Sinatra::Templates#erubis is deprecated and will be removed, use #erb instead.\n" \
        "If you have Erubis installed, it will be used automatically."
      render :erubis, template, options, locals
    end

    def haml(template, options = {}, locals = {}, &block)
      render(:haml, template, options, locals, &block)
    end

    def sass(template, options = {}, locals = {})
      options.merge! :layout => false, :default_content_type => :css
      render :sass, template, options, locals
    end

    def scss(template, options = {}, locals = {})
      options.merge! :layout => false, :default_content_type => :css
      render :scss, template, options, locals
    end

    def less(template, options = {}, locals = {})
      options.merge! :layout => false, :default_content_type => :css
      render :less, template, options, locals
    end

    def stylus(template, options={}, locals={})
      options.merge! :layout => false, :default_content_type => :css
      render :styl, template, options, locals
    end

    def builder(template = nil, options = {}, locals = {}, &block)
      options[:default_content_type] = :xml
      render_ruby(:builder, template, options, locals, &block)
    end

    def liquid(template, options = {}, locals = {}, &block)
      render(:liquid, template, options, locals, &block)
    end

    def markdown(template, options = {}, locals = {})
      render :markdown, template, options, locals
    end

    def textile(template, options = {}, locals = {})
      render :textile, template, options, locals
    end

    def rdoc(template, options = {}, locals = {})
      render :rdoc, template, options, locals
    end

    def asciidoc(template, options = {}, locals = {})
      render :asciidoc, template, options, locals
    end

    def radius(template, options = {}, locals = {})
      render :radius, template, options, locals
    end

    def markaby(template = nil, options = {}, locals = {}, &block)
      render_ruby(:mab, template, options, locals, &block)
    end

    def coffee(template, options = {}, locals = {})
      options.merge! :layout => false, :default_content_type => :js
      render :coffee, template, options, locals
    end

    def nokogiri(template = nil, options = {}, locals = {}, &block)
      options[:default_content_type] = :xml
      render_ruby(:nokogiri, template, options, locals, &block)
    end

    def slim(template, options = {}, locals = {}, &block)
      render(:slim, template, options, locals, &block)
    end

    def creole(template, options = {}, locals = {})
      render :creole, template, options, locals
    end

    def mediawiki(template, options = {}, locals = {})
      render :mediawiki, template, options, locals
    end

    def wlang(template, options = {}, locals = {}, &block)
      render(:wlang, template, options, locals, &block)
    end

    def yajl(template, options = {}, locals = {})
      options[:default_content_type] = :json
      render :yajl, template, options, locals
    end

    def rabl(template, options = {}, locals = {})
      Rabl.register!
      render :rabl, template, options, locals
    end

    # Calls the given block for every possible template file in views,
    # named name.ext, where ext is registered on engine.
    # 尝试各种不同的后缀名来查找模版文件，这个方法主要是遍历各种可能的后缀名
    # 然后组成可能的文件路径，然后交给 block 去生成 Tilt的模版实例
    def find_template(views, name, engine)
      # 调用 block ，返回值是一个 Tilt 的template实例对象
      yield ::File.join(views, "#{name}.#{@preferred_extension}")

      # Tilt 支持将一个特定的后缀名绑定(map)到一种template engine
      # 例如 将 .bar 注册为 erb，那么 Tile 就指导用erb来编译.bar文件
      if Tilt.respond_to?(:mappings)
        # 尝试用注册的mappings的后缀名作为模版的后缀名来查找模版文件
        Tilt.mappings.each do |ext, engines|
          next unless ext != @preferred_extension and engines.include? engine
          yield ::File.join(views, "#{name}.#{ext}")
        end
      else
        # 尝试用默认的mapping的后缀名来尝试查找模版文件
        Tilt.default_mapping.extensions_for(engine).each do |ext|
          yield ::File.join(views, "#{name}.#{ext}") unless ext == @preferred_extension
        end
      end
    end

    private

    # logic shared between builder and nokogiri
    def render_ruby(engine, template, options = {}, locals = {}, &block)
      options, template = template, nil if template.is_a?(Hash)
      template = Proc.new { block } if template.nil?
      render engine, template, options, locals
    end

    # 第一个是 template engine
    # data 可能是一个页面的名字，也可能就是一个页面的内容
    def render(engine, data, options = {}, locals = {}, &block)
      # merge app-level options
      # 获得这个 engine 的配置
      engine_options  = settings.respond_to?(engine) ? settings.send(engine) : {}
      # 将传进来的参数和settings的参数合并
      options.merge!(engine_options) { |key, v1, v2| v1 }

      # extract generic options
      locals          = options.delete(:locals) || locals         || {}
      views           = options.delete(:views)  || settings.views || "./views"
      layout          = options[:layout]
      layout          = false if layout.nil? && options.include?(:layout)
      # 没有 layout
      eat_errors      = layout.nil?
      layout          = engine_options[:layout] if layout.nil? or (layout == true && engine_options[:layout] != false)
      layout          = @default_layout         if layout.nil? or layout == true
      layout_options  = options.delete(:layout_options) || {}
      content_type    = options.delete(:content_type)   || options.delete(:default_content_type)
      # 对于一些不支持layout的template engine，例如 set :rdoc, :layout_engine => :erb
      layout_engine   = options.delete(:layout_engine)  || engine
      scope           = options.delete(:scope)          || self
      options.delete(:layout)

      # set some defaults
      options[:outvar]           ||= '@_out_buf'
      options[:default_encoding] ||= settings.default_encoding

      # compile and render template
      begin
        layout_was      = @default_layout
        @default_layout = false
        template        = compile_template(engine, data, options, views)
        # 这里是将render一个layout，并将 block 的内容包在里面
        output          = template.render(scope, locals, &block)
      ensure
        @default_layout = layout_was
      end

      # render layout
      if layout
        # 这里因为是render一个layout，所以将layout的设置关闭，然后调用 render 将layout包着output的内容render出来
        options = options.merge(:views => views, :layout => false, :eat_errors => eat_errors, :scope => scope).
                merge!(layout_options)
        catch(:layout_missing) { return render(layout_engine, layout, options, locals) { output } }
      end

      output.extend(ContentTyped).content_type = content_type if content_type
      output
    end

    # 将 template 编译成 string
    # engine 是 template engine，例如 erb, slim, haml 等
    # data 可能是指向一个文件，例如 erb :index
    # 也可能是一个inline template
    # 也可能是一个string 或者 block，代表 template 的内容
    # options 是可选项
    # views 是存放 views 的路径，默认是 "./views"，也可能是其他的自定义的路径
    def compile_template(engine, data, options, views)
      eat_errors = options.delete :eat_errors

      # Tilt::Cache#fetch 方法，会查询时候cache中有个，如果有的话，
      # 就用cache的，否则执行block
      template_cache.fetch engine, data, options, views do
        template = Tilt[engine]
        raise "Template engine not found: #{engine}" if template.nil?

        case data
        # 如果是模版指向某个文件 或者 inline 模版
        when Symbol
          # 获得 inline template 数据
          body, path, line = settings.templates[data]
          # 如果是 inline template
          if body
            # 如果 body 能够自解
            body = body.call if body.respond_to?(:call)
            # 然后 返回一个 Tilt 的template实例
            template.new(path, line.to_i, options) { body }
          else
            # 如果不是 inline template，那么就是一个文件
            found = false
            @preferred_extension = engine.to_s
            find_template(views, data, template) do |file|
              # 这个file 是路径 ::File.join(views, "#{name}.#{@preferred_extension})
              path ||= file # keep the initial path rather than the last one
              # 验证这个路径的有效性
              if found = File.exist?(file)
                path = file
                break
              end
            end
            throw :layout_missing if eat_errors and not found
            # 返回一个 Tilt 的template实例
            template.new(path, 1, options)
          end
        # 如果 data 直接是模版的内容
        when Proc, String
           #生成body
          body = data.is_a?(String) ? Proc.new { data } : data
          # 生成路径和行数
          path, line = settings.caller_locations.first
          # 返回一个 Tilt 的template实例
          template.new(path, line.to_i, options, &body)
        else
          raise ArgumentError, "Sorry, don't know how to render #{data.inspect}."
        end
      end
    end
  end

  # Base class for all Sinatra applications and middleware.
  class Base
    include Rack::Utils
    include Helpers
    include Templates

    URI_INSTANCE = URI.const_defined?(:Parser) ? URI::Parser.new : URI

    attr_accessor :app, :env, :request, :response, :params
    # 这是一个 Tilt::Cache 的实例
    attr_reader   :template_cache

    def initialize(app = nil)
      super()
      @app = app
      @template_cache = Tilt::Cache.new
      yield self if block_given?
    end

    # Rack call interface.
    # 这个每个基于Rack的框架的入口
    # 复制一个新的实例，执行call!，让Sinatra跑起来
    def call(env)
      dup.call!(env)
    end

    # 这个方法就是Sinatra开始跑起来的入口了
    def call!(env) # :nodoc:
      # 做一定初始化的工作
      @env      = env
      @request  = Request.new(env)
      @response = Response.new
      @params   = indifferent_params(@request.params)
      # 如果设置了 reload_templates，那么就清除 template_cache
      template_cache.clear if settings.reload_templates
      force_encoding(@params)

      @response['Content-Type'] = nil
      # 处理请求
      invoke { dispatch! }
      # 处理错误
      invoke { error_block!(response.status) } unless @env['sinatra.error']

      # 万一没有设置 Content-Type 根据内容设置，实在没有，就设置为 html
      unless @response['Content-Type']
        if Array === body and body[0].respond_to? :content_type
          content_type body[0].content_type
        else
          content_type :html
        end
      end

      # 结束，设置整个 response 的 Content-Length
      @response.finish
    end

    # Access settings defined with Base.set.
    def self.settings
      self
    end

    # Access settings defined with Base.set.
    def settings
      self.class.settings
    end

    def options
      warn "Sinatra::Base#options is deprecated and will be removed, " \
        "use #settings instead."
      settings
    end

    # Exit the current block, halts any further processing
    # of the request, and returns the specified response.

    # 设置response 然后跳出block
    # 这个的throw会跳出任意层数直到catch那一层
    # 所以这里的 halt 会一直跳出到 invoke 方法
    def halt(*response)
      response = response.first if response.length == 1
      throw :halt, response
    end

    # Pass control to the next matching route.
    # If there are no more matching routes, Sinatra will
    # return a 404 response.

    # 这里的 throw 会跳出block 然后回到 process_route 方法中
    def pass(&block)
      throw :pass, block
    end

    # Forward the request to the downstream app -- middleware only.
    # 如果这是一个中间件，那么forward会向下派送这个请求
    def forward
      fail "downstream app not set" unless @app.respond_to? :call
      # 向下派送给 @app
      status, headers, body = @app.call env
      @response.status = status
      @response.body = body
      @response.headers.merge! headers
      nil
    end

    private

    # Run filters defined on the class and all superclasses.
    # 执行filter的内容，type是 before 或者 after
    def filter!(type, base = settings)
      filter! type, base.superclass if base.superclass.respond_to?(:filters)
      # 遍历每一个 type 类型的filter， 然后
      base.filters[type].each { |args| process_route(*args) }
    end

    # Run routes defined on the class and all superclasses.
    def route!(base = settings, pass_block = nil)

      if routes = base.routes[@request.request_method]
        routes.each do |pattern, keys, conditions, block|
          returned_pass_block = process_route(pattern, keys, conditions) do |*args|
            env['sinatra.route'] = block.instance_variable_get(:@route_name)
            route_eval { block[*args] }
          end

          # don't wipe out pass_block in superclass
          pass_block = returned_pass_block if returned_pass_block
        end
      end

      # Run routes defined in superclass.
      if base.superclass.respond_to?(:routes)
        return route!(base.superclass, pass_block)
      end

      route_eval(&pass_block) if pass_block
      route_missing
    end

    # Run a route block and throw :halt with the result.
    def route_eval
      throw :halt, yield
    end

    # If the current request matches pattern and conditions, fill params
    # with keys and call the given block.
    # Revert params afterwards.
    #
    # Returns pass block.
    # todo 重看
    # 这个方法会匹配路径，如果路径想符合，就给他设置参数
    def process_route(pattern, keys, conditions, block = nil, values = [])
      # 读出请求的路径
      route = @request.path_info
      route = '/' if route.empty? and not settings.empty_path_info?
      # 如果不匹配，就返回
      return unless match = pattern.match(route)
      # 这里把url中的参数都取出来了例如 /restaurant/:rid/food/:fid 就会取出 rid 和 fid
      values += match.captures.map! { |v| force_encoding URI_INSTANCE.unescape(v) if v }

      if values.any?
        # splat 就是route中的星号，会在之后被加进来
        original, @params = params, params.merge('splat' => [], 'captures' => values)
        # todo 再看
        keys.zip(values) { |k,v| Array === @params[k] ? @params[k] << v : @params[k] = v if v }
      end

      # 如果condition也符合，就执行block的内容
      # todo block的内容是什么？
      catch(:pass) do
        conditions.each { |c| throw :pass if c.bind(self).call == false }
        block ? block[self, values] : yield(self, values)
      end
    ensure
      @params = original if original
    end

    # No matching route was found or all routes passed. The default
    # implementation is to forward the request downstream when running
    # as middleware (@app is non-nil); when no downstream app is set, raise
    # a NotFound exception. Subclasses can override this method to perform
    # custom route miss logic.
    # 如果路由找不到，就尝试向下派发(如果是中间件)，否则就是404
    def route_missing
      if @app
        forward
      else
        raise NotFound
      end
    end

    # Attempt to serve static files from public directory. Throws :halt when
    # a matching file is found, returns nil otherwise.
    # 发送静态文件的方法
    def static!(options = {})
      # 必须要设置过静态文件的路径
      return if (public_dir = settings.public_folder).nil?
      # 设置静态文件path
      path = File.expand_path("#{public_dir}#{URI_INSTANCE.unescape(request.path_info)}" )
      # 检查是不是一个文件
      return unless File.file?(path)

      env['sinatra.static_file'] = path
      # 如果需要，设置 cache_control
      cache_control(*settings.static_cache_control) if settings.static_cache_control?
      # 通过 send_file 发送文件
      send_file path, options.merge(:disposition => nil)
    end

    # Enable string or symbol key access to the nested params hash.
    # 将参数转换成对key的类型不敏感的hash
    def indifferent_params(object)
      case object
      when Hash
        new_hash = indifferent_hash
        object.each { |key, value| new_hash[key] = indifferent_params(value) }
        new_hash
      when Array
        object.map { |item| indifferent_params(item) }
      else
        object
      end
    end

    # Creates a Hash with indifferent access.
    # 创建一个 key 可以是 string 或者是 symbol 的hash
    # 就这个方法来说，并不是一个真正的 indifferent_hash
    # 它只做了从 symbol 到 string 的转换，没有做 string 到 symbol 的转换
    # 但是因为原始的数据的key都是string，所以使用起来没问题
    def indifferent_hash
      Hash.new {|hash,key| hash[key.to_s] if Symbol === key }
    end

    # Run the block with 'throw :halt' support and apply result to the response.
    # 这个方法执行一个block，当这个block中有halt方法调用，就会在这个方法捕获
    # 然后根据 halt 后面跟的参数，设置response
    def invoke
      res = catch(:halt) { yield }

      # 如果参数是Interger 或者 String，那么就当作response的status
      res = [res] if Fixnum === res or String === res
      # 如果 参数是数组，并且第一个是 Integer
      # 就设置相应参数
      if Array === res and Fixnum === res.first
        res = res.dup
        status(res.shift)
        body(res.pop)
        headers(*res)
      # 如果 res 是一个能相应 each 的block，就设置成body
      elsif res.respond_to? :each
        body res
      end
      nil # avoid double setting the same response tuple twice
    end

    # Dispatch a request with error handling.
    # 这个方法就开始处理一个请求的入口了
    def dispatch!
      invoke do
        # 如果需要，先处理静态文件
        static! if settings.static? && (request.get? || request.head?)
        # 执行 before filter 的内容
        filter! :before
        route!
      end
    rescue ::Exception => boom
      invoke { handle_exception!(boom) }
    ensure
      begin
        # 执行 after filter的内容
        filter! :after unless env['sinatra.static_file']
      rescue ::Exception => boom
        invoke { handle_exception!(boom) } unless @env['sinatra.error']
      end
    end

    # Error handling during requests.
    # 处理错误信息
    def handle_exception!(boom)

      @env['sinatra.error'] = boom

      # 设置 http 状态码
      if boom.respond_to? :http_status
        status(boom.http_status)
      elsif settings.use_code? and boom.respond_to? :code and boom.code.between? 400, 599
        status(boom.code)
      else
        status(500)
      end

      # 如果 状态码 不是400 到 599，强行设置为 500
      status(500) unless status.between? 400, 599

      # 如果是 500类型的错误
      if server_error?
        # 把错误 dump 出来
        dump_errors! boom if settings.dump_errors?
        # 正常情况，会在浏览器里显示stack trace，除非手动关闭，或者设置了 after_handler
        raise boom if settings.show_exceptions? and settings.show_exceptions != :after_handler
      end

      # 如果是 404 会设置X-cascade 让其他路由去处理
      # 一般是传给其他的中间件去处理这个错误
      if not_found?
        headers['X-Cascade'] = 'pass' if settings.x_cascade?
        body '<h1>Not Found</h1>'
      end

      res = error_block!(boom.class, boom) || error_block!(status, boom)
      return res if res or not server_error?
      raise boom if settings.raise_errors? or settings.show_exceptions?
      error_block! Exception, boom
    end

    # Find an custom error block for the key(s) specified.
    # 找到对应的错误处理的block
    def error_block!(key, *block_params)
      base = settings
      while base.respond_to?(:errors)
        next base = base.superclass unless args_array = base.errors[key]
        args_array.reverse_each do |args|
          first = args == args_array.first
          args += [block_params]
          resp = process_route(*args)
          return resp unless resp.nil? && !first
        end
      end
      return false unless key.respond_to? :superclass and key.superclass < Exception
      error_block!(key.superclass, *block_params)
    end

    # 将错误信息dump出来
    def dump_errors!(boom)
      msg = ["#{Time.now.strftime("%Y-%m-%d %H:%M:%S")} - #{boom.class} - #{boom.message}:", *boom.backtrace].join("\n\t")
      @env['rack.errors'].puts(msg)
    end

    class << self
      CALLERS_TO_IGNORE = [ # :nodoc:
        /\/sinatra(\/(base|main|show_exceptions))?\.rb$/,    # all sinatra code
        /lib\/tilt.*\.rb$/,                                 # all tilt code
        /^\(.*\)$/,                                         # generated code
        /rubygems\/(custom|core_ext\/kernel)_require\.rb$/, # rubygems require hacks
        /active_support/,                                   # active_support require hacks
        /bundler(\/runtime)?\.rb/,                          # bundler require hacks
        /<internal:/,                                       # internal in ruby >= 1.9.2
        /src\/kernel\/bootstrap\/[A-Z]/                     # maglev kernel files
      ]

      # contrary to what the comment said previously, rubinius never supported this
      if defined?(RUBY_IGNORE_CALLERS)
        warn "RUBY_IGNORE_CALLERS is deprecated and will no longer be supported by Sinatra 2.0"
        CALLERS_TO_IGNORE.concat(RUBY_IGNORE_CALLERS)
      end

      attr_reader :routes, :filters, :templates, :errors

      # Removes all routes, filters, middleware and extension hooks from the
      # current class (not routes/filters/... defined by its superclass).
      def reset!
        @conditions     = []
        @routes         = {}
        @filters        = {:before => [], :after => []}
        @errors         = {}
        @middleware     = []
        @prototype      = nil
        @extensions     = []

        if superclass.respond_to?(:templates)
          @templates = Hash.new { |hash,key| superclass.templates[key] }
        else
          @templates = {}
        end
      end

      # Extension modules registered on this class and all superclasses.
      def extensions
        if superclass.respond_to?(:extensions)
          (@extensions + superclass.extensions).uniq
        else
          @extensions
        end
      end

      # Middleware used in this class and all superclasses.
      def middleware
        if superclass.respond_to?(:middleware)
          superclass.middleware + @middleware
        else
          @middleware
        end
      end

      # Sets an option to the given value.  If the value is a proc,
      # the proc will be called every time the option is accessed.
      # 这个方法设置一个option，这个option的值可以是一个普通的对象，也可以是一个block
      # 这里的 not_set 是个小技巧，允许这个方法接受普通对象或者block，值得学习
      def set(option, value = (not_set = true), ignore_setter = false, &block)
        # 如果给了一个block，那么就不应该给值
        # 如果写 set :option, :foo, { block }, 那么not_set 就是nil，这个if条件成立
        raise ArgumentError if block and !not_set
        value, not_set = block, false if block

        # 如果没有给block，而且也没有给value，那么只可能option是一个hash
        # 否则就报错
        if not_set
          raise ArgumentError unless option.respond_to?(:each)
          option.each { |k,v| set(k, v) }
          return self
        end

        # 如果有setter方法，并且可以被赋值
        if respond_to?("#{option}=") and not ignore_setter
          # 调用这个option的setter方法
          return __send__("#{option}=", value)
        end

        # 定义setter和getter方法
        setter = proc { |val| set option, val, true }
        getter = proc { value }

        case value
        # 如果value是个 Proc, 那么getter方法直接就是这个proc
        # 调用getter方法的时候就能获得这个proc的值
        when Proc
          getter = value
        # 如果是个可以直接展示的值，就直接展示
        when Symbol, Fixnum, FalseClass, TrueClass, NilClass
          getter = value.inspect
        # 如果是个Hash， 那么setter方法将值merge到原有的值里
        when Hash
          setter = proc do |val|
            val = value.merge val if Hash === val
            set option, val, true
          end
        end

        # 定义了 getter setter 和 ? 方法
        define_singleton("#{option}=", setter) if setter
        define_singleton(option, getter) if getter
        define_singleton("#{option}?", "!!#{option}") unless method_defined? "#{option}?"
        self
      end

      # Same as calling `set :option, true` for each of the given options.
      # 就是 set :option, true 方法
      def enable(*opts)
        opts.each { |key| set(key, true) }
      end

      # Same as calling `set :option, false` for each of the given options.
      # 就是 set :option, false 方法
      def disable(*opts)
        opts.each { |key| set(key, false) }
      end

      # Define a custom error handler. Optionally takes either an Exception
      # class, or an HTTP status code to specify which errors should be
      # handled.
      # 错误处理函数
      def error(*codes, &block)
        args  = compile! "ERROR", //, block
        codes = codes.map { |c| Array(c) }.flatten
        codes << Exception if codes.empty?
        codes.each { |c| (@errors[c] ||= []) << args }
      end

      # Sugar for `error(404) { ... }`
      def not_found(&block)
        error(404, &block)
        error(Sinatra::NotFound, &block)
      end

      # Define a named template. The block must return the template source.
      def template(name, &block)
        filename, line = caller_locations.first
        templates[name] = [block, filename, line.to_i]
      end

      # Define the layout template. The block must return the template source.
      def layout(name = :layout, &block)
        template name, &block
      end

      # Load embedded templates from the file; uses the caller's __FILE__
      # when no file is specified.
      def inline_templates=(file = nil)
        file = (file.nil? || file == true) ? (caller_files.first || File.expand_path($0)) : file

        begin
          io = ::IO.respond_to?(:binread) ? ::IO.binread(file) : ::IO.read(file)
          app, data = io.gsub("\r\n", "\n").split(/^__END__$/, 2)
        rescue Errno::ENOENT
          app, data = nil
        end

        if data
          if app and app =~ /([^\n]*\n)?#[^\n]*coding: *(\S+)/m
            encoding = $2
          else
            encoding = settings.default_encoding
          end
          lines = app.count("\n") + 1
          template = nil
          force_encoding data, encoding
          data.each_line do |line|
            lines += 1
            if line =~ /^@@\s*(.*\S)\s*$/
              template = force_encoding('', encoding)
              templates[$1.to_sym] = [template, file, lines]
            elsif template
              template << line
            end
          end
        end
      end

      # Lookup or register a mime type in Rack's mime registry.
      def mime_type(type, value = nil)
        return type      if type.nil?
        return type.to_s if type.to_s.include?('/')
        type = ".#{type}" unless type.to_s[0] == ?.
        return Rack::Mime.mime_type(type, nil) unless value
        Rack::Mime::MIME_TYPES[type] = value
      end

      # provides all mime types matching type, including deprecated types:
      #   mime_types :html # => ['text/html']
      #   mime_types :js   # => ['application/javascript', 'text/javascript']
      def mime_types(type)
        type = mime_type type
        type =~ /^application\/(xml|javascript)$/ ? [type, "text/#$1"] : [type]
      end

      # Define a before filter; runs before all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def before(path = nil, options = {}, &block)
        add_filter(:before, path, options, &block)
      end

      # Define an after filter; runs after all requests within the same
      # context as route handlers and may access/modify the request and
      # response.
      def after(path = nil, options = {}, &block)
        add_filter(:after, path, options, &block)
      end

      # add a filter
      def add_filter(type, path = nil, options = {}, &block)
        path, options = //, path if path.respond_to?(:each_pair)
        filters[type] << compile!(type, path || //, block, options)
      end

      # Add a route condition. The route is considered non-matching when the
      # block returns false.
      # 这个方法生成一个condition 方法，加入到 @conditions 列表中
      def condition(name = "#{caller.first[/`.*'/]} condition", &block)
        @conditions << generate_method(name, &block)
      end

      def public=(value)
        warn ":public is no longer used to avoid overloading Module#public, use :public_folder or :public_dir instead"
        set(:public_folder, value)
      end

      def public_dir=(value)
        self.public_folder = value
      end

      def public_dir
        public_folder
      end

      # Defining a `GET` handler also automatically defines
      # a `HEAD` handler.
      # 定义 get 方法的路由
      def get(path, opts = {}, &block)
        conditions = @conditions.dup
        route('GET', path, opts, &block)

        @conditions = conditions
        route('HEAD', path, opts, &block)
      end

      def put(path, opts = {}, &bk)     route 'PUT',     path, opts, &bk end
      def post(path, opts = {}, &bk)    route 'POST',    path, opts, &bk end
      def delete(path, opts = {}, &bk)  route 'DELETE',  path, opts, &bk end
      def head(path, opts = {}, &bk)    route 'HEAD',    path, opts, &bk end
      def options(path, opts = {}, &bk) route 'OPTIONS', path, opts, &bk end
      def patch(path, opts = {}, &bk)   route 'PATCH',   path, opts, &bk end
      def link(path, opts = {}, &bk)    route 'LINK',    path, opts, &bk end
      def unlink(path, opts = {}, &bk)  route 'UNLINK',  path, opts, &bk end

      # Makes the methods defined in the block and in the Modules given
      # in `extensions` available to the handlers and templates
      def helpers(*extensions, &block)
        class_eval(&block)   if block_given?
        include(*extensions) if extensions.any?
      end

      # Register an extension. Alternatively take a block from which an
      # extension will be created and registered on the fly.
      def register(*extensions, &block)
        extensions << Module.new(&block) if block_given?
        @extensions += extensions
        extensions.each do |extension|
          extend extension
          extension.registered(self) if extension.respond_to?(:registered)
        end
      end

      def development?; environment == :development end
      def production?;  environment == :production  end
      def test?;        environment == :test        end

      # Set configuration options for Sinatra and/or the app.
      # Allows scoping of settings for certain environments.
      def configure(*envs)
        yield self if envs.empty? || envs.include?(environment.to_sym)
      end

      # Use the specified Rack middleware
      def use(middleware, *args, &block)
        @prototype = nil
        @middleware << [middleware, args, block]
      end

      # Stop the self-hosted server if running.
      def quit!
        return unless running?
        # Use Thin's hard #stop! if available, otherwise just #stop.
        running_server.respond_to?(:stop!) ? running_server.stop! : running_server.stop
        $stderr.puts "== Sinatra has ended his set (crowd applauds)" unless handler_name =~/cgi/i
        set :running_server, nil
        set :handler_name, nil
      end

      alias_method :stop!, :quit!

      # Run the Sinatra app as a self-hosted server using
      # Thin, Puma, Mongrel, or WEBrick (in that order). If given a block, will call
      # with the constructed handler once we have taken the stage.
      def run!(options = {}, &block)
        return if running?
        set options
        handler         = detect_rack_handler
        handler_name    = handler.name.gsub(/.*::/, '')
        server_settings = settings.respond_to?(:server_settings) ? settings.server_settings : {}
        server_settings.merge!(:Port => port, :Host => bind)

        begin
          start_server(handler, server_settings, handler_name, &block)
        rescue Errno::EADDRINUSE
          $stderr.puts "== Someone is already performing on port #{port}!"
          raise
        ensure
          quit!
        end
      end

      alias_method :start!, :run!

      # Check whether the self-hosted server is running or not.
      def running?
        running_server?
      end

      # The prototype instance used to process requests.
      def prototype
        @prototype ||= new
      end

      # Create a new instance without middleware in front of it.
      alias new! new unless method_defined? :new!

      # Create a new instance of the class fronted by its middleware
      # pipeline. The object is guaranteed to respond to #call but may not be
      # an instance of the class new was called on.
      def new(*args, &bk)
        instance = new!(*args, &bk)
        Wrapper.new(build(instance).to_app, instance)
      end

      # Creates a Rack::Builder instance with all the middleware set up and
      # the given +app+ as end point.
      def build(app)
        builder = Rack::Builder.new
        setup_default_middleware builder
        setup_middleware builder
        builder.run app
        builder
      end

      def call(env)
        synchronize { prototype.call(env) }
      end

      # Like Kernel#caller but excluding certain magic entries and without
      # line / method information; the resulting array contains filenames only.
      def caller_files
        cleaned_caller(1).flatten
      end

      # Like caller_files, but containing Arrays rather than strings with the
      # first element being the file, and the second being the line.
      def caller_locations
        cleaned_caller 2
      end

      private

      # Starts the server by running the Rack Handler.
      def start_server(handler, server_settings, handler_name)
        handler.run(self, server_settings) do |server|
          unless handler_name =~ /cgi/i
            $stderr.puts "== Sinatra (v#{Sinatra::VERSION}) has taken the stage on #{port} for #{environment} with backup from #{handler_name}"
          end

          setup_traps
          set :running_server, server
          set :handler_name,   handler_name
          server.threaded = settings.threaded if server.respond_to? :threaded=

          yield server if block_given?
        end
      end

      def setup_traps
        if traps?
          at_exit { quit! }

          [:INT, :TERM].each do |signal|
            old_handler = trap(signal) do
              quit!
              old_handler.call if old_handler.respond_to?(:call)
            end
          end

          set :traps, false
        end
      end

      # Dynamically defines a method on settings.
      # 动态生成方法，这些方法都是定义在Base上，也就是 settings上
      def define_singleton(name, content = Proc.new)
        # replace with call to singleton_class once we're 1.9 only
        # class << self; self; end方法返回了元类，然后将其打开
        (class << self; self; end).class_eval do
          # 取消定义原来的方法
          undef_method(name) if method_defined? name
          # 定义方法，如果是string，就创建一个方法，是block，就调用 define_method
          String === content ? class_eval("def #{name}() #{content}; end") : define_method(name, &content)
        end
      end

      # Condition for matching host name. Parameter might be String or Regexp.
      #
      def host_name(pattern)
        condition { pattern === request.host }
      end

      # Condition for matching user agent. Parameter should be Regexp.
      # Will set params[:agent].
      def user_agent(pattern)
        condition do
          if request.user_agent.to_s =~ pattern
            @params[:agent] = $~[1..-1]
            true
          else
            false
          end
        end
      end
      alias_method :agent, :user_agent

      # Condition for matching mimetypes. Accepts file extensions.
      def provides(*types)
        types.map! { |t| mime_types(t) }
        types.flatten!
        condition do
          if type = response['Content-Type']
            types.include? type or types.include? type[/^[^;]+/]
          elsif type = request.preferred_type(types)
            params = (type.respond_to?(:params) ? type.params : {})
            content_type(type, params)
            true
          else
            false
          end
        end
      end

      # 这个方法定义了路由
      def route(verb, path, options = {}, &block)
        # Because of self.options.host
        # 如果option中含有 host 则设置设置host_name 作为route的条件
        host_name(options.delete(:host)) if options.key?(:host)
        # empty_path_info 是为了判断是否有空path的路径存在
        # 如果没有，会在没有path的请求最后加上 '/' 结尾
        enable :empty_path_info if path == "" and empty_path_info.nil?
        # signature是一个数组包含
        # - pattern 这个路由对应的正则
        # - keys 这个路由中可以抓到的 key
        # - conditions 匹配这个路由的其他条件
        # - wrapper 这个路由对应的执行方法
        signature = compile!(verb, path, block, options)
        # 将这个signature 放入到对应的路由hash表中
        (@routes[verb] ||= []) << signature
        # 看看添加新的route 会不会触发钩子
        invoke_hook(:route_added, verb, path, block)
        signature
      end

      # 这个方法会查找是否有对应某个名字的钩子
      # 如果有，就执行
      def invoke_hook(name, *args)
        extensions.each { |e| e.send(name, *args) if e.respond_to?(name) }
      end

      # 这个方法也是生成函数，但是生成的是一个Unbound Method
      def generate_method(method_name, &block)
        method_name = method_name.to_sym
        # 这里定义了一个方法在 Sinatra::Base 上
        define_method(method_name, &block)
        # 然后取出这个方法
        method = instance_method method_name
        # 将绑定在Sinatra::Base上的方法删掉
        remove_method method_name
        method
      end

      # 将一个路由编译成 [路由正则，路由中的关键词，路由触发条件，路由处理block]
      def compile!(verb, path, block, options = {})
        # 为每个option 设置值
        options.each_pair { |option, args| send(option, *args) }
        # 创建一个这个route特有的方法名
        method_name             = "#{verb} #{path}"
        # 创建一个unbound 方法 其实就是我们给一个route定义的方法
        unbound_method          = generate_method(method_name, &block)
        # 这里将用户定义的path 转换成 pattern(正则) 和 keys(route中需要匹配的参数)
        pattern, keys           = compile path
        # 把路由的condition保存下载，清空@conditions
        conditions, @conditions = @conditions, []

        # 生成一个叫wrapper的block, artiy 可以获得一个block需要几个参数，需要参数则传参数
        # 不需要参数，直接调用 unbound method
        wrapper                 = block.arity != 0 ?
          proc { |a,p| unbound_method.bind(a).call(*p) } :
          proc { |a,p| unbound_method.bind(a).call }
        # 给这个block设置一个route_name 供之后route! 方法使用
        wrapper.instance_variable_set(:@route_name, method_name)

        [ pattern, keys, conditions, wrapper ]
      end

      def compile(path)
        if path.respond_to? :to_str
          keys = []

          # Split the path into pieces in between forward slashes.
          # A negative number is given as the second argument of path.split
          # because with this number, the method does not ignore / at the end
          # and appends an empty string at the end of the return value.
          #
          segments = path.split('/', -1).map! do |segment|
            ignore = []

            # Special character handling.
            #
            pattern = segment.to_str.gsub(/[^\?\%\\\/\:\*\w]|:(?!\w)/) do |c|
              ignore << escaped(c).join if c.match(/[\.@]/)
              patt = encoded(c)
              patt.gsub(/%[\da-fA-F]{2}/) do |match|
                match.split(//).map! { |char| char == char.downcase ? char : "[#{char}#{char.downcase}]" }.join
              end
            end

            ignore = ignore.uniq.join

            # Key handling.
            #
            pattern.gsub(/((:\w+)|\*)/) do |match|
              if match == "*"
                keys << 'splat'
                "(.*?)"
              else
                keys << $2[1..-1]
                ignore_pattern = safe_ignore(ignore)

                ignore_pattern
              end
            end
          end

          # Special case handling.
          #
          if last_segment = segments[-1] and last_segment.match(/\[\^\\\./)
            parts = last_segment.rpartition(/\[\^\\\./)
            parts[1] = '[^'
            segments[-1] = parts.join
          end
          [/\A#{segments.join('/')}\z/, keys]
        elsif path.respond_to?(:keys) && path.respond_to?(:match)
          [path, path.keys]
        elsif path.respond_to?(:names) && path.respond_to?(:match)
          [path, path.names]
        elsif path.respond_to? :match
          [path, []]
        else
          raise TypeError, path
        end
      end

      def encoded(char)
        enc = URI_INSTANCE.escape(char)
        enc = "(?:#{escaped(char, enc).join('|')})" if enc == char
        enc = "(?:#{enc}|#{encoded('+')})" if char == " "
        enc
      end

      def escaped(char, enc = URI_INSTANCE.escape(char))
        [Regexp.escape(enc), URI_INSTANCE.escape(char, /./)]
      end

      def safe_ignore(ignore)
        unsafe_ignore = []
        ignore = ignore.gsub(/%[\da-fA-F]{2}/) do |hex|
          unsafe_ignore << hex[1..2]
          ''
        end
        unsafe_patterns = unsafe_ignore.map! do |unsafe|
          chars = unsafe.split(//).map! do |char|
            char == char.downcase ? char : char + char.downcase
          end

          "|(?:%[^#{chars[0]}].|%[#{chars[0]}][^#{chars[1]}])"
        end
        if unsafe_patterns.length > 0
          "((?:[^#{ignore}/?#%]#{unsafe_patterns.join()})+)"
        else
          "([^#{ignore}/?#]+)"
        end
      end

      def setup_default_middleware(builder)
        builder.use ExtendedRack
        builder.use ShowExceptions       if show_exceptions?
        builder.use Rack::MethodOverride if method_override?
        builder.use Rack::Head
        setup_logging    builder
        setup_sessions   builder
        setup_protection builder
      end

      def setup_middleware(builder)
        middleware.each { |c,a,b| builder.use(c, *a, &b) }
      end

      def setup_logging(builder)
        if logging?
          setup_common_logger(builder)
          setup_custom_logger(builder)
        elsif logging == false
          setup_null_logger(builder)
        end
      end

      def setup_null_logger(builder)
        builder.use Rack::NullLogger
      end

      def setup_common_logger(builder)
        builder.use Sinatra::CommonLogger
      end

      def setup_custom_logger(builder)
        if logging.respond_to? :to_int
          builder.use Rack::Logger, logging
        else
          builder.use Rack::Logger
        end
      end

      def setup_protection(builder)
        return unless protection?
        options = Hash === protection ? protection.dup : {}
        protect_session  = options.fetch(:session) { sessions? }
        options[:except] = Array options[:except]
        options[:except] += [:session_hijacking, :remote_token] unless protect_session
        options[:reaction] ||= :drop_session
        builder.use Rack::Protection, options
      end

      def setup_sessions(builder)
        return unless sessions?
        options = {}
        options[:secret] = session_secret if session_secret?
        options.merge! sessions.to_hash if sessions.respond_to? :to_hash
        builder.use Rack::Session::Cookie, options
      end

      def detect_rack_handler
        servers = Array(server)
        servers.each do |server_name|
          begin
            return Rack::Handler.get(server_name.to_s)
          rescue LoadError, NameError
          rescue ArgumentError
            Sinatra::Ext.get_handler(server_name.to_s)
          end
        end
        fail "Server handler (#{servers.join(',')}) not found."
      end

      def inherited(subclass)
        subclass.reset!
        subclass.set :app_file, caller_files.first unless subclass.app_file?
        super
      end

      @@mutex = Mutex.new
      def synchronize(&block)
        if lock?
          @@mutex.synchronize(&block)
        else
          yield
        end
      end

      # used for deprecation warnings
      def warn(message)
        super message + "\n\tfrom #{cleaned_caller.first.join(':')}"
      end

      # Like Kernel#caller but excluding certain magic entries
      def cleaned_caller(keep = 3)
        caller(1).
          map!    { |line| line.split(/:(?=\d|in )/, 3)[0,keep] }.
          reject { |file, *_| CALLERS_TO_IGNORE.any? { |pattern| file =~ pattern } }
      end
    end

    # Fixes encoding issues by
    # * defaulting to UTF-8
    # * casting params to Encoding.default_external
    #
    # The latter might not be necessary if Rack handles it one day.
    # Keep an eye on Rack's LH #100.
    def force_encoding(*args) settings.force_encoding(*args) end
    if defined? Encoding
      def self.force_encoding(data, encoding = default_encoding)
        return if data == settings || data.is_a?(Tempfile)
        if data.respond_to? :force_encoding
          data.force_encoding(encoding).encode!
        elsif data.respond_to? :each_value
          data.each_value { |v| force_encoding(v, encoding) }
        elsif data.respond_to? :each
          data.each { |v| force_encoding(v, encoding) }
        end
        data
      end
    else
      def self.force_encoding(data, *) data end
    end

    reset!

    set :environment, (ENV['RACK_ENV'] || :development).to_sym
    set :raise_errors, Proc.new { test? }
    set :dump_errors, Proc.new { !test? }
    set :show_exceptions, Proc.new { development? }
    set :sessions, false
    set :logging, false
    set :protection, true
    set :method_override, false
    set :use_code, false
    set :default_encoding, "utf-8"
    set :x_cascade, true
    set :add_charset, %w[javascript xml xhtml+xml].map { |t| "application/#{t}" }
    settings.add_charset << /^text\//

    # explicitly generating a session secret eagerly to play nice with preforking
    begin
      require 'securerandom'
      set :session_secret, SecureRandom.hex(64)
    rescue LoadError, NotImplementedError
      # SecureRandom raises a NotImplementedError if no random device is available
      set :session_secret, "%064x" % Kernel.rand(2**256-1)
    end

    class << self
      alias_method :methodoverride?, :method_override?
      alias_method :methodoverride=, :method_override=
    end

    set :run, false                       # start server via at-exit hook?
    set :running_server, nil
    set :handler_name, nil
    set :traps, true
    set :server, %w[HTTP webrick]
    set :bind, Proc.new { development? ? 'localhost' : '0.0.0.0' }
    set :port, Integer(ENV['PORT'] && !ENV['PORT'].empty? ? ENV['PORT'] : 4567)

    ruby_engine = defined?(RUBY_ENGINE) && RUBY_ENGINE

    if ruby_engine == 'macruby'
      server.unshift 'control_tower'
    else
      server.unshift 'reel'
      server.unshift 'mongrel'  if ruby_engine.nil?
      server.unshift 'puma'     if ruby_engine != 'rbx'
      server.unshift 'thin'     if ruby_engine != 'jruby'
      server.unshift 'puma'     if ruby_engine == 'rbx'
      server.unshift 'trinidad' if ruby_engine == 'jruby'
    end

    set :absolute_redirects, true
    set :prefixed_redirects, false
    set :empty_path_info, nil

    set :app_file, nil
    set :root, Proc.new { app_file && File.expand_path(File.dirname(app_file)) }
    set :views, Proc.new { root && File.join(root, 'views') }
    set :reload_templates, Proc.new { development? }
    set :lock, false
    set :threaded, true

    set :public_folder, Proc.new { root && File.join(root, 'public') }
    set :static, Proc.new { public_folder && File.exist?(public_folder) }
    set :static_cache_control, false

    error ::Exception do
      response.status = 500
      content_type 'text/html'
      '<h1>Internal Server Error</h1>'
    end

    configure :development do
      get '/__sinatra__/:image.png' do
        filename = File.dirname(__FILE__) + "/images/#{params[:image].to_i}.png"
        content_type :png
        send_file filename
      end

      error NotFound do
        content_type 'text/html'

        if self.class == Sinatra::Application
          code = <<-RUBY.gsub(/^ {12}/, '')
            #{request.request_method.downcase} '#{request.path_info}' do
              "Hello World"
            end
          RUBY
        else
          code = <<-RUBY.gsub(/^ {12}/, '')
            class #{self.class}
              #{request.request_method.downcase} '#{request.path_info}' do
                "Hello World"
              end
            end
          RUBY

          file = settings.app_file.to_s.sub(settings.root.to_s, '').sub(/^\//, '')
          code = "# in #{file}\n#{code}" unless file.empty?
        end

        (<<-HTML).gsub(/^ {10}/, '')
          <!DOCTYPE html>
          <html>
          <head>
            <style type="text/css">
            body { text-align:center;font-family:helvetica,arial;font-size:22px;
              color:#888;margin:20px}
            #c {margin:0 auto;width:500px;text-align:left}
            </style>
          </head>
          <body>
            <h2>Sinatra doesn&rsquo;t know this ditty.</h2>
            <img src='#{uri "/__sinatra__/404.png"}'>
            <div id="c">
              Try this:
              <pre>#{Rack::Utils.escape_html(code)}</pre>
            </div>
          </body>
          </html>
        HTML
      end
    end
  end

  # Execution context for classic style (top-level) applications. All
  # DSL methods executed on main are delegated to this class.
  #
  # The Application class should not be subclassed, unless you want to
  # inherit all settings, routes, handlers, and error pages from the
  # top-level. Subclassing Sinatra::Base is highly recommended for
  # modular applications.
  class Application < Base
    set :logging, Proc.new { ! test? }
    set :method_override, true
    set :run, Proc.new { ! test? }
    set :session_secret, Proc.new { super() unless development? }
    set :app_file, nil

    def self.register(*extensions, &block) #:nodoc:
      added_methods = extensions.map {|m| m.public_instance_methods }.flatten
      Delegator.delegate(*added_methods)
      super(*extensions, &block)
    end
  end

  # Sinatra delegation mixin. Mixing this module into an object causes all
  # methods to be delegated to the Sinatra::Application class. Used primarily
  # at the top-level.
  module Delegator #:nodoc:
    def self.delegate(*methods)
      methods.each do |method_name|
        define_method(method_name) do |*args, &block|
          return super(*args, &block) if respond_to? method_name
          Delegator.target.send(method_name, *args, &block)
        end
        private method_name
      end
    end

    delegate :get, :patch, :put, :post, :delete, :head, :options, :link, :unlink,
             :template, :layout, :before, :after, :error, :not_found, :configure,
             :set, :mime_type, :enable, :disable, :use, :development?, :test?,
             :production?, :helpers, :settings, :register

    class << self
      attr_accessor :target
    end

    self.target = Application
  end

  class Wrapper
    def initialize(stack, instance)
      @stack, @instance = stack, instance
    end

    def settings
      @instance.settings
    end

    def helpers
      @instance
    end

    def call(env)
      @stack.call(env)
    end

    def inspect
      "#<#{@instance.class} app_file=#{settings.app_file.inspect}>"
    end
  end

  # Create a new Sinatra application; the block is evaluated in the class scope.
  def self.new(base = Base, &block)
    base = Class.new(base)
    base.class_eval(&block) if block_given?
    base
  end

  # Extend the top-level DSL with the modules provided.
  def self.register(*extensions, &block)
    Delegator.target.register(*extensions, &block)
  end

  # Include the helper modules provided in Sinatra's request context.
  def self.helpers(*extensions, &block)
    Delegator.target.helpers(*extensions, &block)
  end

  # Use the middleware for classic applications.
  def self.use(*args, &block)
    Delegator.target.use(*args, &block)
  end
end
