#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <ctime>
#include <unordered_map>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = asio::ip::tcp;

struct Url {
    std::string scheme, host, port, path;
};

Url parse_url(const std::string& url) {
    auto p = url.find("://"); if (p==std::string::npos) throw std::invalid_argument("Invalid URL format");
    Url u; u.scheme = url.substr(0,p);
    size_t host_start = p+3;
    size_t path_pos = url.find('/', host_start);
    std::string hostport = (path_pos==std::string::npos) ? url.substr(host_start) : url.substr(host_start, path_pos - host_start);
    size_t colon = hostport.find(':');
    if (colon!=std::string::npos) { u.host = hostport.substr(0, colon); u.port = hostport.substr(colon+1); }
    else { u.host = hostport; u.port = (u.scheme=="https"?"443":"80"); }
    u.path = (path_pos==std::string::npos) ? "/" : url.substr(path_pos);
    return u;
}
void save_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    if (outfile.empty()) return;
    std::ofstream ofs(outfile, std::ios::binary);
    if (!ofs) throw std::runtime_error("Failed to open output file");
    for (auto const& cb : res.body().data()) { const char* ptr = boost::asio::buffer_cast<const char*>(cb); std::size_t len = boost::asio::buffer_size(cb); ofs.write(ptr, static_cast<std::streamsize>(len)); }
} 
std::string handle_redirect(const http::response<http::dynamic_body>& res, const std::string& url, std::string& redirect_url, size_t& redirects) {
    if (res.result_int() < 300 || res.result_int() >= 400) return "";
    if (res.base().count(http::field::location)) {
        redirect_url = res.base()[http::field::location].to_string();
    } else {
        const size_t MAX_INSPECT = 8192; bool is_html = false;
        if (res.base().count(http::field::content_type)) {
            std::string ct = std::string(res.base()[http::field::content_type]);
            if (ct.find("text/html") != std::string::npos) is_html = true;
        }
        if (is_html) {
            std::string snippet; snippet.reserve(MAX_INSPECT);
            size_t copied = 0;
            for (auto const& cb : res.body().data()) {
                size_t len = boost::asio::buffer_size(cb);
                const char* data = static_cast<const char*>(boost::asio::buffer_cast<const void*>(cb));
                size_t to_copy = (len < MAX_INSPECT - copied ? len : MAX_INSPECT - copied);
                snippet.append(data, to_copy);
                copied += to_copy; if (copied >= MAX_INSPECT) break;
            }
            auto find_between = [&](const std::string& key)->std::string{
                auto p = snippet.find(key);
                if (p==std::string::npos) return std::string(); p += key.size();
                while (p < snippet.size() && (snippet[p]==' '||snippet[p]=='='||snippet[p]=='\"'||snippet[p]=='\'')) ++p;
                size_t q = p; while (q < snippet.size() && snippet[q] != '"' && snippet[q] != '\'' && snippet[q] != '>' && snippet[q] != ' ' && snippet[q] != ';') ++q;
                return snippet.substr(p, q-p);
            };
            redirect_url = find_between("url="); if (redirect_url.empty()) redirect_url = find_between("href=");
        }
    }
    if (redirect_url.empty()) return "";
    if (redirect_url.rfind("//", 0) == 0) {
        size_t scheme_end = url.find("://"); std::string scheme = (scheme_end!=std::string::npos)?url.substr(0,scheme_end):"http";
        redirect_url = scheme + ":" + redirect_url;
    }
    if (redirect_url.rfind("http", 0) != 0) {
        size_t scheme_end = url.find("://"); if (scheme_end != std::string::npos) {
            std::string scheme = url.substr(0, scheme_end); size_t host_start = scheme_end + 3;
            size_t path_pos = url.find('/', host_start);
            std::string host = (path_pos == std::string::npos) ? url.substr(host_start) : url.substr(host_start, path_pos - host_start);
            if (!redirect_url.empty() && redirect_url[0] == '/') redirect_url = scheme + "://" + host + redirect_url; else redirect_url = scheme + "://" + host + "/" + redirect_url;
        }
    }
    ++redirects; if (redirects>10){ std::cerr<<"Error: Too many redirects\n"; std::cout<<"error: Too many redirects\n"; return ""; } return redirect_url;
}

template<typename Stream> void perform_request(Stream& stream, const Url& parsed_url, http::response<http::dynamic_body>& res) { http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11}; req.set(http::field::host, parsed_url.host); req.set(http::field::user_agent, "mycurl"); http::write(stream, req); beast::flat_buffer buffer; http::read(stream, buffer, res); }

void get_url(std::string& url, const std::string& output_file) {
    try {
        Url parsed_url = parse_url(url);

        asio::io_context io_context;
        tcp::resolver resolver(io_context);

        std::unordered_map<std::string, tcp::resolver::results_type> dns_cache;

        tcp::resolver::results_type results;
        std::string hp = parsed_url.host + ":" + parsed_url.port;
        auto cache_it = dns_cache.find(hp);
        if (cache_it != dns_cache.end()) {
            results = cache_it->second;
        } else {
            results = resolver.resolve(parsed_url.host, parsed_url.port);
            dns_cache.emplace(hp, results);
        }

        std::string redirect_url;
        size_t redirects = 0;
        size_t body_size = 0;

        auto start_time = std::chrono::steady_clock::now();

        while (true) {
            http::response<http::dynamic_body> res;

            if (parsed_url.scheme == "https") {
                ssl::context ssl_context(ssl::context::tls_client);
                ssl::stream<tcp::socket> ssl_stream(io_context, ssl_context);
                asio::connect(ssl_stream.next_layer(), results.begin(), results.end());
                ssl_stream.handshake(ssl::stream_base::client);

                perform_request(ssl_stream, parsed_url, res);
            } else {
                tcp::socket socket(io_context);
                asio::connect(socket, results.begin(), results.end());

                perform_request(socket, parsed_url, res);
            }

            redirect_url = handle_redirect(res, url, redirect_url, redirects);
            if (redirect_url.empty()) { body_size = res.body().size(); save_response(res, output_file); break; }

            url = redirect_url;
            parsed_url = parse_url(url);

            std::string hp2 = parsed_url.host + ":" + parsed_url.port;
            auto it2 = dns_cache.find(hp2);
            if (it2 != dns_cache.end()) {
                results = it2->second;
            } else {
                results = resolver.resolve(parsed_url.host, parsed_url.port);
                dns_cache.emplace(hp2, results);
            }
            redirect_url.clear();
        }

        auto end_time = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double>(end_time - start_time).count();
        double mbps = (body_size * 8.0) / (duration * 1e6);
        std::cout << std::time(nullptr) << " " << url << " " << body_size << " " << duration << " " << mbps << "\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        std::cout << "error: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string url;
    std::string output_file;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o") {
            if (i + 1 < argc) {
                output_file = argv[++i];
            } else {
                std::cerr << "Error: Missing argument for -o" << std::endl;
                std::cout << "error: Missing argument for -o" << std::endl;
                return 1;
            }
        } else if (arg.rfind("--output", 0) == 0) {
            auto pos = arg.find('=');
            if (pos != std::string::npos) {
                output_file = arg.substr(pos + 1);
            } else {
                if (i + 1 < argc) {
                    output_file = argv[++i];
                } else {
                    std::cerr << "Error: Missing argument for --output" << std::endl;
                    std::cout << "error: Missing argument for --output" << std::endl;
                    return 1;
                }
            }
        } else if (!arg.empty() && arg[0] == '-') {
            std::string optname = arg.size() > 1 ? arg.substr(1) : arg;
            std::cerr << "Error: Invalid option -- '" << optname << "'" << std::endl;
            std::cout << "error: invalid option -- '" << optname << "'" << std::endl;
            std::cerr << "Usage: " << argv[0] << " [-o output_file] URL" << std::endl;
            std::cout << "error: Usage: " << argv[0] << " [-o output_file] URL" << std::endl;
            return 1;
        } else {
            if (url.empty()) url = arg;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required!" << std::endl;
        std::cout << "error: URL is required!" << std::endl;
        return 1;
    }
    get_url(url, output_file);
    return 0;
}
