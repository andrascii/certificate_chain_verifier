#include "finally.h"

namespace verifier
{

Finally::Finally(const std::function<void()>& callable)
	: m_callable(callable)
{
}

Finally::~Finally()
{
	m_callable();
}

}