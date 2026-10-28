#pragma once
#include <algorithm>
#include <string>
#include <string_view>

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
