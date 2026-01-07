#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/asio/ssl.hpp>
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>
#include <iomanip>
#include <getopt.h>
#include <sstream>

namespace asio  = boost::asio;
namespace ssl   = boost::asio::ssl;
namespace beast = boost::beast;
namespace http  = beast::http;
using tcp       = asio::ip::tcp;

class HttpClient {
public:
    HttpClient(const std::string& url, const std::string& outputFile)
        : url_(url), outputFile_(outputFile), ioContext_(), resolver_(ioContext_)
    {
        parseUrl();
    }

    void makeRequest() {
        resolve();
        if (protocol_ == "https") {
            sslStream_ = std::make_unique<ssl::stream<tcp::socket>>(ioContext_, sslContext_);
            connectSsl();
            makeRequestInternal();
        } else {
            socket_ = std::make_unique<tcp::socket>(ioContext_);
            connect();
            makeRequestInternal();
        }
    }

private:
    std::string url_, outputFile_;
    asio::io_context ioContext_;
    tcp::resolver resolver_;
    std::unique_ptr<tcp::socket> socket_;
    std::unique_ptr<ssl::stream<tcp::socket>> sslStream_;
    ssl::context sslContext_{ssl::context::tls_client};
    std::string host_, path_, port_, protocol_;
    int redirectCount_ = 0;

    void parseUrl() {
        size_t pos = url_.find("://");
        if (pos == std::string::npos) throw std::runtime_error("Invalid URL");

        protocol_ = url_.substr(0, pos);
        std::string remainder = url_.substr(pos + 3);

        pos = remainder.find('/');
        host_ = (pos == std::string::npos) ? remainder : remainder.substr(0, pos);
        path_ = (pos == std::string::npos) ? "/" : remainder.substr(pos);

        port_ = (protocol_ == "https") ? "443" : "80";
    }

    void resolve() {
        auto endpoints = resolver_.resolve(host_, port_);
        if (protocol_ == "https") {
            socket_ = nullptr; // No TCP socket needed for SSL stream, it's handled by sslStream_
        }
        else {
            socket_ = std::make_unique<tcp::socket>(ioContext_);
            asio::connect(*socket_, endpoints);
        }
    }

    void connectSsl() {
        asio::connect(sslStream_->next_layer(), resolver_.resolve(host_, port_));
        sslStream_->handshake(ssl::stream_base::client);
    }

    void connect() {
        asio::connect(*socket_, resolver_.resolve(host_, port_));
    }

    void makeRequestInternal() {
        http::request<http::empty_body> req{http::verb::get, path_, 11};
        req.set(http::field::host, host_);
        req.set(http::field::user_agent, "mycurl");

        if (protocol_ == "https") {
            http::write(*sslStream_, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(*sslStream_, buffer, res);
            handleResponse(res);
        } else {
            http::write(*socket_, req);
            beast::flat_buffer buffer;
            http::response<http::dynamic_body> res;
            http::read(*socket_, buffer, res);
            handleResponse(res);
        }
    }

    void handleResponse(http::response<http::dynamic_body>& res) {
        if (res.result_int() >= 300 && res.result_int() < 400) {
            std::string redirectUrl = res.base()[http::field::location].to_string();
            if (redirectCount_ < 10) {
                redirectCount_++;
                std::cout << "Redirecting to: " << redirectUrl << std::endl;
                url_ = redirectUrl;
                makeRequest();
                return;
            } else {
                throw std::runtime_error("Too many redirects");
            }
        }

        if (!outputFile_.empty()) {
            std::ofstream ofs(outputFile_, std::ios::binary);
            if (!ofs) {
                throw std::runtime_error("Failed to open output file");
            }
            ofs << beast::buffers_to_string(res.body().data());
            ofs.flush();
        }

        logDownloadDetails(res.body().size());
    }

    void logDownloadDetails(size_t bodySize) {
        auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - startTime_).count();
        double mbps = (bodySize * 8.0) / (duration * 1e6);
        auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::cout << std::put_time(std::localtime(&now), "%F %T") << " "
                  << url_ << " "
                  << bodySize << " [bytes] "
                  << duration << " [s] "
                  << mbps << " [Mbps]" << std::endl;
    }

    std::chrono::steady_clock::time_point startTime_ = std::chrono::steady_clock::now();
};

int main(int argc, char* argv[]) {
    try {
        std::string outputFile;
        static option options[] = {
            {"output", required_argument, nullptr, 'o'},
            {nullptr, 0, nullptr, 0}
        };

        int opt;
        while ((opt = getopt_long(argc, argv, "o:", options, nullptr)) != -1) {
            if (opt == 'o') {
                outputFile = optarg;
            } else {
                std::cerr << "Error: Unsupported option" << std::endl;
                return 1;
            }
        }

        if (optind >= argc) {
            std::cerr << "Error: Missing URL argument" << std::endl;
            return 1;
        }

        std::string url = argv[optind];

        HttpClient client(url, outputFile);
        client.makeRequest();

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
