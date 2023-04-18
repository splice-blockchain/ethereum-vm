// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "tracing.hpp"
#include <evmc/evmc.h>
#include <fstream>
#include <vector>

#if defined(_MSC_VER) && !defined(__clang__)
#define EVMONE_CGOTO_SUPPORTED 0
#else
#define EVMONE_CGOTO_SUPPORTED 1
#endif

namespace evmone
{
/// The evmone EVMC instance.
class VM : public evmc_vm
{
public:
    bool cgoto = EVMONE_CGOTO_SUPPORTED;

private:
    std::unique_ptr<Tracer> m_first_tracer;
    std::vector<std::ofstream> m_tracing_outputs;

public:
    inline VM() noexcept;

    void add_tracer(std::unique_ptr<Tracer> tracer) noexcept
    {
        // Find the first empty unique_ptr and assign the new tracer to it.
        auto* end = &m_first_tracer;
        while (*end)
            end = &(*end)->m_next_tracer;
        *end = std::move(tracer);
    }

    void add_standard_tracer(std::string_view output_name) noexcept;

    void remove_tracers() noexcept
    {
        m_first_tracer = nullptr;
        m_tracing_outputs.clear();
    }

    [[nodiscard]] Tracer* get_tracer() const noexcept { return m_first_tracer.get(); }
};
}  // namespace evmone
