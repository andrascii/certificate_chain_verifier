#pragma once

#include <functional>

namespace verifier
{

class Finally
{
public:
	Finally(const Finally&) = delete;
	Finally(Finally&&) = delete;

	Finally(const std::function<void()>& callable);
	~Finally();

private:
	std::function<void()> m_callable;
};

}