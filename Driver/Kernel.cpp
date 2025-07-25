#include "pch.h"
#include "Kernel.h"
#if __has_include("Kernel.g.cpp")
#include "Kernel.g.cpp"
#endif

using namespace winrt;
using namespace Windows::UI::Xaml;

namespace winrt::Driver::implementation
{
    int32_t Kernel::MyProperty()
    {
        throw hresult_not_implemented();
    }

    void Kernel::MyProperty(int32_t /* value */)
    {
        throw hresult_not_implemented();
    }

    void Kernel::ClickHandler(IInspectable const&, RoutedEventArgs const&)
    {
        Button().Content(box_value(L"Clicked"));
    }
}
