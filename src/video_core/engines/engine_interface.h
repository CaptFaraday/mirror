// SPDX-FileCopyrightText: Copyright 2026 Eden Emulator Project
// SPDX-License-Identifier: GPL-3.0-or-later

// SPDX-FileCopyrightText: Copyright 2020 yuzu Emulator Project
// SPDX-License-Identifier: GPL-2.0-or-later

#pragma once

#include <array>

#include <boost/container/small_vector.hpp>

#include "common/common_types.h"

namespace Tegra::Engines {

enum class EngineTypes : u32 {
    Nv01Timer,
    KeplerCompute,
    Maxwell3D,
    Fermi2D,
    MaxwellDMA,
    KeplerMemory,
};

class EngineInterface {
public:
    virtual ~EngineInterface() = default;

    /// Write the value to the register identified by method.
    virtual void CallMethod(u32 method, u32 method_argument, bool is_last_call) = 0;

    /// Write multiple values to the register identified by method.
    virtual void CallMultiMethod(u32 method, const u32* base_start, u32 amount,
                                 u32 methods_pending) = 0;

    void ConsumeSink() {
        if (method_sink.empty()) {
            return;
        }
        ConsumeSinkImpl();
    }

    static constexpr size_t EXECUTION_MASK_TABLE_SIZE = 0xE00;

    std::array<u8, EXECUTION_MASK_TABLE_SIZE> execution_mask{};
    bool execution_mask_default{};
    boost::container::small_vector<std::pair<u32, u32>, 64> method_sink{};
    bool current_dirty{};
    GPUVAddr current_dma_segment;

protected:
    virtual void ConsumeSinkImpl() {
        for (auto [method, value] : method_sink) {
            CallMethod(method, value, true);
        }
        method_sink.clear();
    }
};

} // namespace Tegra::Engines
