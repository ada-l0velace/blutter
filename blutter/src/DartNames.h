#pragma once
#include <algorithm>
#include <string>
#include <string_view>
#include <stdexcept>

inline std::string DartLibraryFileName(std::string_view url)
{
	if (!url.starts_with("dart:")) throw std::invalid_argument("Expected a Dart SDK library URL");
	const auto name = url.substr(5);
	if (name.empty() || name == "." || name == ".." ||
		name.find_first_of("/\\:") != std::string_view::npos ||
		std::any_of(name.begin(), name.end(), [](unsigned char c) { return c < 0x20 || c == 0x7f; }))
		throw std::invalid_argument("Invalid Dart SDK library filename");
	return std::string(name) + ".dart";
}

inline std::string LibraryDisplayName(std::string_view url)
{
	std::string out;
	if (url.starts_with("package:")) out = url.substr(8);
	else if (url.starts_with("file:")) {
		auto offset = url.rfind('/');
		if (offset != std::string_view::npos) offset = url.rfind('/', offset - 1);
		out = url.substr(offset == std::string_view::npos ? 0 : offset + 1);
	}
	else {
		out = url;
		if (url.starts_with("dart:")) out[4] = '_';
	}
	if (out.ends_with(".dart")) out.erase(out.length() - 5);
	std::replace(out.begin(), out.end(), '/', '$');
	return out;
}
