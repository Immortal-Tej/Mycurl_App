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

void handle_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    std::cout << "Response Status: " << res.result() << "\n";
    for (const auto& header : res.base()) {
        std::cout << header.name_string() << ": " << header.value() << "\n";
    }

    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        if (!ofs) {
            throw std::runtime_error("Failed to open output file");
        }
        ofs << boost::beast::buffers_to_string(res.body().data());
    }
}

std::optional<std::string> handle_redirect(http::response<http::dynamic_body>& res, const std::string& url, size_t& redirects, std::set<std::string>& visited_urls) {
    if (res.result_int() >= 300 && res.result_int() < 400 && res.base().count(http::field::location)) {
        std::string redirect_url = res.base()[http::field::location].to_string();

        if (redirect_url.empty() || visited_urls.find(redirect_url) != visited_urls.end() || redirect_url == url) {
            return std::nullopt; // Stop redirect
        }

        if (redirect_url.rfind("//", 0) == 0) {
            size_t scheme_end = url.find("://");
            std::string scheme = (scheme_end != std::string::npos) ? url.substr(0, scheme_end) : "http";
            redirect_url = scheme + ":" + redirect_url;
        }

        if (redirect_url.rfind("http", 0) != 0) {
            size_t scheme_end = url.find("://");
            std::string scheme = url.substr(0, scheme_end);
            size_t host_start = scheme_end + 3;
            size_t path_pos = url.find('/', host_start);
            std::string host = (path_pos == std::string::npos) ? url.substr(host_start) : url.substr(host_start, path_pos - host_start);
            redirect_url = scheme + "://" + host + (redirect_url[0] == '/' ? redirect_url : "/" + redirect_url);
        }

        visited_urls.insert(redirect_url);
        ++redirects;
        if (redirects > 10) {
            std::cerr << "Error: Too many redirects\n";
            return std::nullopt; // Stop after 10 redirects
        }

        std::cout << "Redirecting to: " << redirect_url << "\n";
        return redirect_url;
    }
    return std::nullopt; // No redirect
}

void get_url(std::string& url, const std::string& output_file) {
    try {
        Url parsed_url = parse_url(url);

        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);

        auto results = resolver.resolve(parsed_url.host, parsed_url.port);
        std::set<std::string> visited_urls;
        visited_urls.insert(url);

        size_t redirects = 0, body_size = 0;
        auto start_time = Clock::now();

        while (true) {
            bool is_https = parsed_url.scheme == "https";
            std::unique_ptr<asio::stream_base> stream;
            if (is_https) {
                ssl::context ssl_context(ssl::context::tls_client);
                stream = std::make_unique<ssl::stream<tcp::socket>>(io_context, ssl_context);
            } else {
                stream = std::make_unique<tcp::socket>(io_context);
            }

            asio::connect(stream->next_layer(), results.begin(), results.end());
            if (is_https) {
                static_cast<ssl::stream<tcp::socket>&>(*stream).handshake(ssl::stream_base::client);
            }

            http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
            req.set(http::field::host, parsed_url.host);
            req.set(http::field::user_agent, "mycurl");

            http::write(*stream, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(*stream, buffer, res);

            handle_response(res, output_file);
            auto redirect_url = handle_redirect(res, url, redirects, visited_urls);
            if (!redirect_url) {
                body_size = res.body().size();
                break;
            }

            url = *redirect_url;
            parsed_url = parse_url(url);
            results = resolver.resolve(parsed_url.host, parsed_url.port);
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
    }
}

int main(int argc, char* argv[]) {
    std::string url;
    std::string output_file;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" || arg.rfind("--output", 0) == 0) {
            output_file = (i + 1 < argc) ? argv[++i] : "";
            if (output_file.empty()) {
                std::cerr << "Error: Missing argument for -o\n";
                return 1;
            }
        } else {
            url = arg;
        }
    }

    if (url.empty()) {
        std::cerr << "URL is required!\n";
        return 1;
    }

    get_url(url, output_file);
    return 0;
}
