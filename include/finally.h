#pragma once

#include <functional>

class Finally
{
public:
	Finally(const Finally&) = delete;
	Finally(Finally&&) = delete;

	Finally(const std::function<void()>& callable)
		: m_callable(callable)
	{
	}

	~Finally()
	{
		m_callable();
	}

private:
	std::function<void()> m_callable;
};