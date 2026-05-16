#include "constrict/DecisionLog.hpp"

#include <sstream>
#include <string_view>
#include <system_error>

namespace pc::constrict {

namespace {

void write_csv_field(std::ostream& out, const std::string_view value) {
    out.put('"');
    for (const char ch : value) {
        if (ch == '"') {
            out.put('"');
        }
        out.put(ch);
    }
    out.put('"');
}

void write_csv_row(std::ostream& out, const DecisionLogRow& row) {
    out << row.packet_index << ',';
    write_csv_field(out, row.src_ip);
    out << ',' << row.src_port << ',';
    write_csv_field(out, row.dst_ip);
    out << ',' << row.dst_port << ',';
    write_csv_field(out, row.transport);
    out << ',' << row.tcp_seq
        << ',' << row.tcp_ack << ',';
    write_csv_field(out, row.tcp_flags);
    out << ',' << row.captured_length_before
        << ',' << row.captured_length_after
        << ',' << row.original_length
        << ',' << row.transport_payload_size << ',';
    write_csv_field(out, row.decision);
    out << ',';
    write_csv_field(out, row.reason);
    out << ',' << row.bytes_saved << ',';
    write_csv_field(out, row.tls_state_before);
    out << ',';
    write_csv_field(out, row.tls_state_after);
    out << ',' << row.tls_active_record_remaining_before
        << ',' << row.tls_active_record_remaining_after << ',';
    write_csv_field(out, row.tls_record_event);
    out << ',';
    write_csv_field(out, row.decode_note);
    out << '\n';
}

}  // namespace

bool DecisionLogWriter::open(const std::filesystem::path& path) {
    std::error_code error {};
    const auto parent = path.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent, error);
        if (error) {
            has_error_ = true;
            error_message_ = "failed to create decision log directory";
            return false;
        }
    }

    stream_ = std::ofstream(path, std::ios::binary | std::ios::trunc);
    if (!stream_.is_open()) {
        has_error_ = true;
        error_message_ = "failed to open decision log file";
        return false;
    }

    stream_
        << "packet_index,src_ip,src_port,dst_ip,dst_port,transport,tcp_seq,tcp_ack,tcp_flags,"
        << "captured_length_before,captured_length_after,original_length,transport_payload_size,"
        << "decision,reason,bytes_saved,tls_state_before,tls_state_after,"
        << "tls_active_record_remaining_before,tls_active_record_remaining_after,"
        << "tls_record_event,decode_note\n";
    if (!stream_) {
        has_error_ = true;
        error_message_ = "failed to write decision log header";
        return false;
    }

    return true;
}

bool DecisionLogWriter::write_row(const DecisionLogRow& row) {
    if (!stream_.is_open()) {
        has_error_ = true;
        error_message_ = "decision log file is not open";
        return false;
    }

    write_csv_row(stream_, row);
    if (!stream_) {
        has_error_ = true;
        error_message_ = "failed to write decision log row";
        return false;
    }

    return true;
}

void DecisionLogWriter::close() {
    if (stream_.is_open()) {
        stream_.flush();
        if (!stream_) {
            has_error_ = true;
            error_message_ = "failed to flush decision log file";
        }
        stream_.close();
    }
}

bool DecisionLogWriter::has_error() const noexcept {
    return has_error_;
}

const std::string& DecisionLogWriter::error_message() const noexcept {
    return error_message_;
}

}  // namespace pc::constrict
