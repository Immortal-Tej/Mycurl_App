#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <iomanip>
#include <regex>
#include <set>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = boost::asio::ssl;
using tcp = asio::ip::tcp;
using Clock = std::chrono::steady_clock;

struct Url {
    std::string scheme, host, port, path;
};

Url parse_url(const std::string& url) {
    std::regex url_regex("(https?)://([^/:]+)(?::(\\d+))?(/.*)?");
    std::smatch match;
    if (!std::regex_match(url, match, url_regex)) {
        throw std::invalid_argument("Invalid URL format");
    }

    Url parsed_url;
    parsed_url.scheme = match[1].str();
    parsed_url.host = match[2].str();
    parsed_url.path = match[4].matched ? match[4].str() : "/";

    parsed_url.port = match[3].matched ? match[3].str() : (parsed_url.scheme == "https" ? "443" : "80");

    return parsed_url;
}

void print_response(const http::response<http::dynamic_body>& res) {
    std::cout << "Response Status: " << res.result() << "\n";
    for (const auto& header : res.base()) {
        std::cout << header.name_string() << ": " << header.value() << "\n";
    }
}

void save_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Failed to open output file");
        }
        ofs << boost::beast::buffers_to_string(res.body().data());
        ofs.close();
    }
}

std::string handle_redirect(http::response<http::dynamic_body>& res, const std::string& url, std::string& redirect_url, size_t& redirects, std::set<std::string>& visited_urls) {
    if (res.result_int() >= 300 && res.result_int() < 400) {
        if (res.base().count(http::field::location)) {
            redirect_url = res.base()[http::field::location].to_string();
        } else {
            try {
                std::string body = boost::beast::buffers_to_string(res.body().data());
                std::smatch m;
                std::regex meta_re("<meta[^>]*refresh[^>]*content=[\"']?\s*\d+;\s*url=([^\"'>]+)[\"'>]?", std::regex::icase);
                std::regex href_re("<a[^>]*href=[\"']?([^\"'>]+)[\"'>]?", std::regex::icase);
                if (std::regex_search(body, m, meta_re) && m.size() > 1) {
                    redirect_url = m[1].str();
                } else if (std::regex_search(body, m, href_re) && m.size() > 1) {
                    redirect_url = m[1].str();
                }
            } catch (...) {}
        }

        if (!redirect_url.empty()) {
            if (redirect_url.rfind("//", 0) == 0) {
                size_t scheme_end = url.find("://");
                std::string scheme = (scheme_end != std::string::npos) ? url.substr(0, scheme_end) : "http";
                redirect_url = scheme + ":" + redirect_url;
            }

            if (redirect_url.rfind("http", 0) != 0) {
                size_t scheme_end = url.find("://");
                if (scheme_end != std::string::npos) {
                    std::string scheme = url.substr(0, scheme_end);
                    size_t host_start = scheme_end + 3;
                    size_t path_pos = url.find('/', host_start);
                    std::string host = (path_pos == std::string::npos) ? url.substr(host_start) : url.substr(host_start, path_pos - host_start);
                    if (!redirect_url.empty() && redirect_url[0] == '/') {
                        redirect_url = scheme + "://" + host + redirect_url;
                    } else {
                        redirect_url = scheme + "://" + host + "/" + redirect_url;
                    }
                }
            }

            if (visited_urls.find(redirect_url) != visited_urls.end() || redirect_url == url) {
                std::cout << "Redirect loop detected, stopping...\n";
                return "";
            }

            std::cout << "Redirecting to: " << redirect_url << "\n";
            visited_urls.insert(redirect_url);
            ++redirects;
            if (redirects > 10) {
                std::cerr << "Error: Too many redirects\n";
                std::cout << "error: Too many redirects\n";
                return "";
            }
            return redirect_url;
        }
    }
    return "";
}

void get_url(std::string& url, const std::string& output_file) {
    try {
        Url parsed_url = parse_url(url);

        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);

        auto results = resolver.resolve(parsed_url.host, parsed_url.port);

        std::string redirect_url;
        size_t redirects = 0;
        size_t body_size = 0;

        std::set<std::string> visited_urls;
        visited_urls.insert(url);

        auto start_time = Clock::now();

        while (true) {
            if (parsed_url.scheme == "https") {
                ssl::context ssl_context(ssl::context::tls_client);
                ssl::stream<tcp::socket> ssl_stream(io_context, ssl_context);
                asio::connect(ssl_stream.next_layer(), results.begin(), results.end());
                ssl_stream.handshake(ssl::stream_base::client);

                http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
                req.set(http::field::host, parsed_url.host);
                req.set(http::field::user_agent, "mycurl");

                http::write(ssl_stream, req);
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::read(ssl_stream, buffer, res);

                print_response(res);
                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);
                if (redirect_url.empty()) {
                    body_size = res.body().size();
                    save_response(res, output_file);
                    break;
                }
            } else {
                asio::connect(socket, results.begin(), results.end());

                http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
                req.set(http::field::host, parsed_url.host);
                req.set(http::field::user_agent, "mycurl");

                http::write(socket, req);
                beast::flat_buffer buffer;
                http::response<http::dynamic_body> res;
                http::read(socket, buffer, res);

                print_response(res);
                redirect_url = handle_redirect(res, url, redirect_url, redirects, visited_urls);
                if (redirect_url.empty()) {
                    body_size = res.body().size();
                    save_response(res, output_file);
                    break;
                }
            }

            if (!redirect_url.empty()) {
                url = redirect_url;
                parsed_url = parse_url(url);
                results = resolver.resolve(parsed_url.host, parsed_url.port);
                visited_urls.insert(url);
                redirect_url.clear();

                if (socket.is_open()) {
                    boost::system::error_code ec;
                    socket.close(ec);
                }

                continue;
            }
        }

        auto end_time = Clock::now();
        auto duration = std::chrono::duration<double>(end_time - start_time).count();
        double mbps = (body_size * 8.0) / (duration * 1e6);

        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
                  << url << " " << body_size << " [bytes] "
                  << duration << " [s] "
                  << mbps << " [Mbps]\n";

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
            if (url.empty()) {
                url = arg;
            } else {
            }
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
