#pragma once

#include "Kernel.g.h"

namespace winrt::Driver::implementation
{
    struct Kernel : KernelT<Kernel>
    {
        Kernel() 
        {
            // Xaml objects should not call InitializeComponent during construction.
            // See https://github.com/microsoft/cppwinrt/tree/master/nuget#initializecomponent
        }

        int32_t MyProperty();
        void MyProperty(int32_t value);

        void ClickHandler(Windows::Foundation::IInspectable const& sender, Windows::UI::Xaml::RoutedEventArgs const& args);
    };
}

namespace winrt::Driver::factory_implementation
{
    struct Kernel : KernelT<Kernel, implementation::Kernel>
    {
    };
}
