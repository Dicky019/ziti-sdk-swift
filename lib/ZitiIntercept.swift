/*
Copyright NetFoundry Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
import Foundation
import CZitiPrivate

class ZitiIntercept : NSObject, ZitiUnretained {
    private let log = ZitiLog(ZitiIntercept.self)
    
    let name:String
    let urlStr:String
    var clt = tlsuv_http_t()
    var zs = tlsuv_src_t()
    var hdrs:[String:String]? = nil
    
    static var releasePending:[ZitiIntercept] = []

    init(_ ziti:Ziti, _ name:String, _ urlStr:String, _ idleTime:Int) {
        self.name = name
        self.urlStr = urlStr
        ziti_src_init(ziti.loop, &zs, name.cString(using: .utf8), ziti.ztx)
        tlsuv_http_init_with_src(ziti.loop, &clt, urlStr.cString(using: .utf8), &zs)
        tlsuv_http_idle_keepalive(&clt, idleTime)
        
        super.init()
        
        clt.data = self.toVoidPtr()
        
        if let tls_context = clt.tls {
            tls_context.pointee.set_cert_verify?(tls_context, { _, _ in
                return 0
            }, nil)
            tlsuv_http_set_ssl(&clt, tls_context)
            log.trace("Trying to set ssl verification off")
        } else if let tls_context = default_tls_context(nil, 0) { // apakah code ini sudah benar, untuk mentrust ssl server?
            tls_context.pointee.set_cert_verify?(tls_context, { one, two in
                let log = ZitiLog(ZitiIntercept.self)
                log.trace("Trying to trust server ssl")
                return 0
            }, nil)
            tlsuv_http_set_ssl(&clt, tls_context)
            log.trace("Trying to create tls_context")
        } else {
            log.trace("tlsContextnya nil")
        }
    }
    
    static private let on_http_close:tlsuv_http_close_cb = { h in
        guard let ctx = h?.pointee.data, let mySelf = zitiUnretained(ZitiIntercept.self, ctx) else {
            return
        }
        releasePending = releasePending.filter { $0 != mySelf }
    }
    
    func close() {
        ZitiIntercept.releasePending.append(self)
        tlsuv_http_close(&clt, ZitiIntercept.on_http_close)
    }
    
    func createRequest(_ zup:ZitiUrlProtocol, _ urlPath:String,
                       _ on_resp:@escaping tlsuv_http_resp_cb,
                       _ on_body:@escaping tlsuv_http_body_cb,
                       _ ctx:UnsafeMutableRawPointer) -> UnsafeMutablePointer<tlsuv_http_req_t>? {
        
        var req:UnsafeMutablePointer<tlsuv_http_req_t>? = nil
        
        let method = zup.request.httpMethod ?? "GET"
        req = tlsuv_http_req(&clt, method, urlPath.cString(using: .utf8), on_resp, ctx)
        req?.pointee.resp.body_cb = on_body
        
        if req != nil {
           let data = zup.request.allHTTPHeaderFields ?? [:]
           let headers = data.filter { $0.key != "httpBody" }
           let httpBody = data["httpBody"]
           
           log.info("-- zup.request.allHTTPHeaderFields: \(headers.debugDescription)")
           log.info("-- zup.request.httpBody: \(httpBody?.debugDescription ?? "nil")")
            // Add request headers
            headers.forEach { h in
                tlsuv_http_req_header(req,
                                   h.key.cString(using: .utf8),
                                   h.value.cString(using: .utf8))
            }
            
            // add any headers specified via service config
            if let hdrs = hdrs {
                hdrs.forEach { hdr in
                    tlsuv_http_req_header(req, hdr.key, hdr.value)
                }
            }
            
            // if no User-Agent add it
            if headers["User-Agent"] == nil {
                var zv = "unknown-@unknown"
                if let nfv = ziti_get_version()?.pointee {
                    zv = "\(String(cString: nfv.version))-@\(String(cString: nfv.revision))"
                }
                tlsuv_http_req_header(req,
                                   "User-Agent".cString(using: .utf8),
                                   "\(ZitiUrlProtocol.self); ziti-sdk-c/\(zv)".cString(using: .utf8))
            }
            
            // if no Accept, add it
            if headers["Accept"] == nil {
                tlsuv_http_req_header(req,
                                   "Accept".cString(using: .utf8),
                                   "*/*".cString(using: .utf8))
            }
            // Add body
            if let httpBody, let body = httpBody.data(using: .utf8) {
                let ptr = UnsafeMutablePointer<Int8>.allocate(capacity: body.count)
                let bytes:[Int8] = body.map{ Int8(bitPattern: $0) }
                ptr.initialize(from: bytes, count: body.count)
                tlsuv_http_req_data(req, ptr, body.count, nil)
                ptr.deallocate()
            } else if let body = zup.request.httpBody {
                log.info("-- zup.request.httpBody: \(String(data: body, encoding: .utf8)?.debugDescription ?? "-")")
                
                let ptr = UnsafeMutablePointer<Int8>.allocate(capacity: body.count)
                let bytes:[Int8] = body.map{ Int8(bitPattern: $0) }
                ptr.initialize(from: bytes, count: body.count)
                tlsuv_http_req_data(req, ptr, body.count, nil)
                ptr.deallocate()
            } else if let stream = zup.request.httpBodyStream {
                log.info("-- zup.request.httpBody :: .httpBodyStream")
                if let clv = zup.request.allHTTPHeaderFields?["Content-Length"], let contentLen = Int(clv) {
                    var body = Data()
                    let ptr = UnsafeMutablePointer<UInt8>.allocate(capacity: contentLen)
                    stream.open()
                    while stream.hasBytesAvailable {
                        let n = stream.read(ptr, maxLength: contentLen)
                        body.append(ptr, count: n)
                    }
                    stream.close()
                  
                    log.info("-- zup.request.httpBodyStream: \(String(data: body, encoding: .utf8)?.debugDescription ?? "-")")

                    let _ptr = UnsafeMutablePointer<Int8>.allocate(capacity: body.count)
                    let bytes:[Int8] = body.map{ Int8(bitPattern: $0) }
                    _ptr.initialize(from: bytes, count: body.count)
                    tlsuv_http_req_data(req, _ptr, body.count, nil)

                    _ptr.deallocate()
                    ptr.deallocate()
                } else {
                    log.info("-- zup.request.httpBody :: encoding not yet supported :(")
                    // TODO: Transfer-Encoding:chunked
                    let encoding = headers["Transfer-Encoding"] ?? ""
                    log.error("Content-Length required, \(encoding) encoding not yet supported :(")
                }
            } else {
              log.info("-- zup.request.httpBody :: else")
            }
          
          log.info("-- Final Req: \(req)")
        }

        return req
    }
}