#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/beast.hpp>
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
    if (!std::regex_match(url, match, url_regex)) throw std::invalid_argument("Invalid URL format");
    return {match[1], match[2], match[3].matched ? match[3] : (match[1] == "https" ? "443" : "80"), match[4].matched ? match[4] : "/"};
}

void handle_response(const http::response<http::dynamic_body>& res, const std::string& outfile) {
    std::cout << "Response Status: " << res.result() << "\n";
    for (const auto& header : res.base()) std::cout << header.name_string() << ": " << header.value() << "\n";
    if (!outfile.empty()) {
        std::ofstream ofs(outfile, std::ios::binary);
        if (!ofs) throw std::runtime_error("Failed to open output file");
        ofs << boost::beast::buffers_to_string(res.body().data());
    }
}

std::optional<std::string> handle_redirect(http::response<http::dynamic_body>& res, const std::string& url, size_t& redirects, std::set<std::string>& visited_urls) {
    if (res.result_int() >= 300 && res.result_int() < 400 && res.base().count(http::field::location)) {
        std::string redirect_url = res.base()[http::field::location].to_string();
        if (redirect_url.empty() || visited_urls.find(redirect_url) != visited_urls.end() || redirect_url == url) return std::nullopt;
        if (redirect_url.rfind("//", 0) == 0) redirect_url = url.substr(0, url.find("://")) + ":" + redirect_url;
        if (redirect_url.rfind("http", 0) != 0) redirect_url = url.substr(0, url.find("://")) + "://" + url.substr(url.find("://") + 3, url.find("/", url.find("://") + 3) - url.find("://") - 3) + "/" + redirect_url;
        visited_urls.insert(redirect_url);
        ++redirects;
        if (redirects > 10) { std::cerr << "Error: Too many redirects\n"; return std::nullopt; }
        return redirect_url;
    }
    return std::nullopt;
}

void get_url(std::string& url, const std::string& output_file) {
    try {
        Url parsed_url = parse_url(url);
        asio::io_context io_context;
        tcp::resolver resolver(io_context);
        tcp::socket socket(io_context);
        auto results = resolver.resolve(parsed_url.host, parsed_url.port);
        std::set<std::string> visited_urls{url};
        size_t redirects = 0, body_size = 0;
        auto start_time = Clock::now();

        while (true) {
            std::unique_ptr<asio::stream_base> stream = (parsed_url.scheme == "https")
                ? std::make_unique<ssl::stream<tcp::socket>>(io_context, ssl::context(ssl::context::tls_client))
                : std::make_unique<tcp::socket>(io_context);
            asio::connect(stream->next_layer(), results.begin(), results.end());
            if (parsed_url.scheme == "https") static_cast<ssl::stream<tcp::socket>&>(*stream).handshake(ssl::stream_base::client);

            http::request<http::empty_body> req{http::verb::get, parsed_url.path, 11};
            req.set(http::field::host, parsed_url.host);
            req.set(http::field::user_agent, "mycurl");
            http::write(*stream, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(*stream, buffer, res);

            handle_response(res, output_file);
            auto redirect_url = handle_redirect(res, url, redirects, visited_urls);
            if (!redirect_url) { body_size = res.body().size(); break; }
            url = *redirect_url;
            parsed_url = parse_url(url);
            results = resolver.resolve(parsed_url.host, parsed_url.port);
        }

        auto duration = std::chrono::duration<double>(Clock::now() - start_time).count();
        double mbps = (body_size * 8.0) / (duration * 1e6);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " " << url << " " << body_size << " [bytes] " << duration << " [s] " << mbps << " [Mbps]\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
}

int main(int argc, char* argv[]) {
    std::string url, output_file;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-o" || arg.rfind("--output", 0) == 0) output_file = (i + 1 < argc) ? argv[++i] : "";
        else url = arg;
    }

    if (url.empty()) { std::cerr << "URL is required!\n"; return 1; }
    get_url(url, output_file);
    return 0;
}
