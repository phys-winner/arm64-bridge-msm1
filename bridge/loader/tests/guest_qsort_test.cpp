#include "dynarmic_host.h"
#include "thunk_manager.h"
#include "thunk_types.h"
#include "guest_qsort_image.h"
#include "thunks_opensles.h"
#include "telltale_addcallback_fastpath.h"
#include "telltale_propertyset_fastpath.h"
#include <SLES/OpenSLES.h>
#include <EGL/egl.h>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <mutex>

#include <algorithm>
#include <array>
#include <barrier>
#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <vector>

// Small instruction fixtures deliberately exercise the production SVC/BLX path.
static void Load(std::vector<uint32_t>& code, unsigned reg, uint32_t value) {
    code.push_back(0xE3000000u | (reg << 12) | ((value & 0xF000u) << 4) | (value & 0xFFFu)); // movw
    value >>= 16;
    code.push_back(0xE3400000u | (reg << 12) | ((value & 0xF000u) << 4) | (value & 0xFFFu)); // movt
}

static void Call(std::vector<uint32_t>& code, uint32_t target) {
    Load(code, 12, target);
    code.push_back(0xE12FFF3C); // blx ip
}

template<typename T>
static uint32_t Install(DynarmicHost& host, const std::vector<T>& code) {
    const uint32_t address = host.GuestAlloc(code.size() * sizeof(T), 4);
    assert(address);
    memcpy(host.GetGuestMemoryBase() + address, code.data(), code.size() * sizeof(T));
    host.AddExecutableRange(address, code.size() * sizeof(T));
    host.InvalidateGuestCode(address, code.size() * sizeof(T));
    return address;
}

static void ThumbCall(std::vector<uint16_t>& code, uint32_t target) {
    if (code.size() % 2) code.push_back(0xBF00); // align literal PC
    code.insert(code.end(), {0x4C00, 0xE001, static_cast<uint16_t>(target),
                             static_cast<uint16_t>(target >> 16), 0x47A0, 0xBF00}); // ldr r4; b; literal; blx r4
}

static bool AudioPumpCheck(DynarmicHost& host, bool no_pump) {
    using namespace std::chrono_literals;
    std::atomic<bool> finished{false};
    std::thread deadline([&] {
        const auto end = std::chrono::steady_clock::now()+20s;
        while (!finished && std::chrono::steady_clock::now() < end) std::this_thread::sleep_for(10ms);
        if (!finished) { fputs("Audio regression timed out (possible lifecycle deadlock)\n",stderr); std::_Exit(2); }
    });
    auto& manager = host.GetThunkManager();
    PauseAudioPlayback(&host); // Backgrounding during FMOD startup must be remembered.
    const auto player = OpenSLESTestPrepare(host,no_pump);
    assert(player.player && player.queue && player.play);
    const uint32_t reg = manager.GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback");
    const uint32_t enqueue = manager.GetOrCreateThunkAddress("SLBufferQueue_Enqueue");
    const uint32_t clear = manager.GetOrCreateThunkAddress("SLBufferQueue_Clear");
    const uint32_t play = manager.GetOrCreateThunkAddress("SLPlay_SetPlayState");
    const uint32_t destroy = manager.GetOrCreateThunkAddress("SLObject_Destroy");
    const uint32_t pcm = host.GuestAlloc(32), context = host.GuestAlloc(8);
    assert(pcm && context);
    memset(host.GetGuestMemoryBase()+pcm,0x19,32);
    host.MemoryWrite32(context,0xABCDEFAA);
    const std::thread::id caller_thread = std::this_thread::get_id();
    std::mutex mutex;
    std::condition_variable cv;
    bool hold = false, entered = false;
    std::atomic<unsigned> invocations{0};
    const uint32_t enter = manager.RegisterThunk("__audio_test_enter",[&](Dynarmic::A32::Jit& jit,DynarmicHost& active) {
        assert(&active == &host && active.IsJitRunning() && std::this_thread::get_id() != caller_thread);
        assert(jit.Regs()[0] == player.queue && jit.Regs()[1] == context && host.MemoryRead32(context) == 0xABCDEFAA);
        assert((jit.Regs()[13] & 7) == 0);
        // A different worker must acquire this mutex while the callback is running.
        bool acquired = false;
        std::thread probe([&] {
            std::lock_guard<std::recursive_mutex> host_lock(host.GetMutex());
            std::lock_guard<std::mutex> lock(mutex); acquired = true; cv.notify_all();
        });
        {
            std::unique_lock<std::mutex> lock(mutex);
            assert(cv.wait_for(lock,2s,[&] { return acquired; }));
            entered = true; cv.notify_all();
            assert(cv.wait_for(lock,2s,[&] { return !hold; }));
        }
        probe.join();
        jit.Regs()[1] = pcm; jit.Regs()[2] = 16;
    });
    const uint32_t leave = manager.RegisterThunk("__audio_test_leave",[&](Dynarmic::A32::Jit& jit,DynarmicHost&) {
        assert(jit.Regs()[0] == SL_RESULT_SUCCESS); // callback re-enqueued through the production thunk
        ++invocations;
    });
    std::vector<uint32_t> arm{0xE92D4010};
    Call(arm,enter); Call(arm,enqueue); Call(arm,leave);
    arm.insert(arm.end(),{0xE8BD4010,0xE12FFF1E});
    const uint32_t callback = Install(host,arm);
    std::vector<uint16_t> thumb{0xB510};
    ThumbCall(thumb,enter); ThumbCall(thumb,enqueue); ThumbCall(thumb,leave);
    thumb.push_back(0xBD10);
    const uint32_t thumb_callback = Install(host,thumb) | 1;
    auto wait_callbacks = [&](uint64_t count) {
        const auto deadline = std::chrono::steady_clock::now()+2s;
        while (std::chrono::steady_clock::now() < deadline) {
            if (OpenSLESTestInspect().callbacks >= count) return true;
            std::this_thread::sleep_for(1ms);
        }
        return false;
    };
    auto call = [&](uint32_t function, std::initializer_list<uint32_t> args) {
        return host.RunFunction(function,std::vector<uint32_t>(args));
    };
    assert(call(reg,{player.queue,callback,context}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,callback,context}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PLAYING);
    OpenSLESTestComplete(); OpenSLESTestComplete();
    if (!wait_callbacks(2)) {
        fprintf(stderr,"Audio regression FAILED: two completions did not reach guest refill (candidate125 missing-start reproduction=%d)\n",no_pump);
        ShutdownOpenSLES(&host);
        finished = true; deadline.join();
        return false;
    }
    assert(OpenSLESTestInspect().starts == 1 && invocations == 2 && OpenSLESTestInspect().enqueues == 4);

    PauseAudioPlayback(&host);
    assert(call(play,{player.play,SL_PLAYSTATE_PAUSED}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    OpenSLESTestComplete(); // A buffer completed before pause; its acknowledgment remains valid.
    if (!wait_callbacks(3)) {
        fputs("Audio regression FAILED: real completion acknowledgment withheld while PAUSED\n",stderr);
        ShutdownOpenSLES(&host);
        finished = true; deadline.join();
        return false;
    }
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_PAUSED);
    // Only the guest's explicit request resumes hardware, after its acknowledgment.
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    assert(call(play,{player.play,SL_PLAYSTATE_STOPPED}) == SL_RESULT_SUCCESS);
    PauseAudioPlayback(&host); ResumeAudioPlayback(&host);
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_STOPPED);
    OpenSLESTestComplete(); assert(wait_callbacks(4));
    assert(OpenSLESTestInspect().native_state == SL_PLAYSTATE_STOPPED);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);

    PauseAudioPlayback(&host);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    OpenSLESTestComplete(true); // notification from an old buffer, after native index reset
    ResumeAudioPlayback(&host); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 4);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    {
        std::lock_guard<std::mutex> lock(mutex); hold = true; entered = false;
    }
    OpenSLESTestComplete();
    {
        std::unique_lock<std::mutex> lock(mutex); assert(cv.wait_for(lock,2s,[&] { return entered; }));
    }
    std::atomic<bool> unregistered{false};
    std::thread unregister([&] {
        assert(call(reg,{player.queue,0,0}) == SL_RESULT_SUCCESS);
        unregistered = true;
    });
    std::this_thread::sleep_for(30ms);
    assert(!unregistered);
    {
        std::lock_guard<std::mutex> lock(mutex); hold = false; cv.notify_all();
    }
    unregister.join();
    assert(wait_callbacks(5));
    host.MemoryWrite32(context,0xDEADBEEF); // guest may now release its callback context
    OpenSLESTestComplete(); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 5);
    host.MemoryWrite32(context,0xABCDEFAA);
    assert(call(play,{player.play,SL_PLAYSTATE_STOPPED}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,thumb_callback,context}) == SL_RESULT_SUCCESS);
    assert(OpenSLESTestInspect().starts == 1);
    assert(call(play,{player.play,SL_PLAYSTATE_PLAYING}) == SL_RESULT_SUCCESS);
    OpenSLESTestComplete(); assert(wait_callbacks(6));
    assert(invocations == 6);

    const auto before_bad = OpenSLESTestInspect();
    for (const auto& args : std::vector<std::vector<uint32_t>>{
             {player.queue,0,16},{player.queue,UINT32_MAX-1,16},{player.queue,pcm,16388},
             {player.queue,pcm,0},{player.queue,pcm,3},{player.queue+4,pcm,16}})
        assert(host.RunFunction(enqueue,args) != SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,pcm,context}) == SL_RESULT_PARAMETER_INVALID);
    assert(call(reg,{player.queue,callback|2u,context}) == SL_RESULT_PARAMETER_INVALID);
    assert(OpenSLESTestInspect().enqueues == before_bad.enqueues && OpenSLESTestInspect().buffer_hash == before_bad.buffer_hash);
    OpenSLESTestError(SL_RESULT_RESOURCE_ERROR);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_RESOURCE_ERROR);
    assert(OpenSLESTestInspect().enqueues == before_bad.enqueues && OpenSLESTestInspect().buffer_hash == before_bad.buffer_hash);
    OpenSLESTestError(SL_RESULT_SUCCESS);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    for (unsigned i = 0; i < 128; ++i) assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_SUCCESS);
    const auto full = OpenSLESTestInspect();
    memset(host.GetGuestMemoryBase()+pcm,0x55,32);
    assert(call(enqueue,{player.queue,pcm,16}) == SL_RESULT_BUFFER_INSUFFICIENT);
    assert(OpenSLESTestInspect().enqueues == full.enqueues && OpenSLESTestInspect().buffer_hash == full.buffer_hash);
    assert(call(clear,{player.queue}) == SL_RESULT_SUCCESS);
    assert(call(reg,{player.queue,0,0}) == SL_RESULT_SUCCESS);
    call(destroy,{player.player});
    OpenSLESTestComplete(true); std::this_thread::sleep_for(30ms);
    assert(OpenSLESTestInspect().callbacks == 6 && OpenSLESTestInspect().queue == 0);
    ShutdownOpenSLES(&host);
    assert(OpenSLESTestInspect().queue == 0);
    {
        DynarmicHost teardown;
        assert(teardown.Initialize());
        const auto other = OpenSLESTestPrepare(teardown,false);
        const uint32_t idle_callback = Install(teardown,std::vector<uint32_t>{0xE12FFF1E});
        const uint32_t register_other = teardown.GetThunkManager().GetOrCreateThunkAddress("SLBufferQueue_RegisterCallback");
        assert(teardown.RunFunction(register_other,{other.queue,idle_callback,0}) == SL_RESULT_SUCCESS);
        assert(OpenSLESTestInspect().starts == 1);
    } // destructor must stop/join before destroying the guest JIT and memory
    assert(OpenSLESTestInspect().queue == 0);
    puts("Audio pump checks OK: production registration, ARM/Thumb callbacks, exact args/counts, distinct JIT, re-enqueue without host lock, pause/STOPPED, Clear late notification, unregister quiescence, destroy/join, invalid/full/native-error");
    fflush(stdout);
    finished = true; deadline.join();
    return true;
}

static void AeabiMemoryCheck(DynarmicHost& host) {
    const char* names[][3] = {
        {"__aeabi_memcpy", "__aeabi_memcpy4", "__aeabi_memcpy8"},
        {"__aeabi_memmove", "__aeabi_memmove4", "__aeabi_memmove8"},
        {"__aeabi_memset", "__aeabi_memset4", "__aeabi_memset8"},
        {"__aeabi_memclr", "__aeabi_memclr4", "__aeabi_memclr8"}};
    const uint32_t storage = host.GuestAlloc(64, 8); assert(storage);
    auto* bytes = host.GetGuestMemoryBase() + storage;
    for (unsigned op = 0; op < 4; ++op) for (const char* name : names[op]) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
        assert(fn);
        std::vector<uint32_t> code{0xE92D4010}; Call(code, fn);
        code.insert(code.end(), {0xE8BD4010, 0xE3A0005A, 0xE12FFF1E}); // continuation marker, not an AEABI return value
        const uint32_t caller = Install(host, code);
        for (uint32_t n : {0u, 13u}) for (bool reverse : {false, true}) {
            std::array<uint8_t, 64> expected; expected.fill(0xA5);
            for (unsigned i = 8; i < 56; ++i) expected[i] = static_cast<uint8_t>(i * 7 + 3);
            memcpy(bytes, expected.data(), expected.size());
            const uint32_t d = reverse ? 16 : 8, s = op == 0 ? 40 : reverse ? 8 : 16;
            if (op < 2) memmove(expected.data() + d, expected.data() + s, n);
            else memset(expected.data() + d, op == 2 ? 0x5A : 0, n);
            const auto args = op < 2 ? std::vector<uint32_t>{storage+d, storage+s, n} : std::vector<uint32_t>{storage+d, n, 0x15A};
            assert(host.RunFunction(caller, args) == 90 && !host.IsJitRunning());
            assert(memcmp(bytes, expected.data(), expected.size()) == 0);
        }
        assert(host.RunFunction(caller, {0, 0, 0}) == 90);
    }
    host.GuestFree(storage);
    puts("AEABI memory checks OK: 12 variants, byte counts, overlap, fill argument order, canaries, zero count");
}

static void PendingInvalidationCheck(DynarmicHost& host) {
    const uint32_t function = Install(host, std::vector<uint32_t>{0xE3A00001, 0xE12FFF1E}); // mov r0,#1; bx lr
    assert(host.RunFunction(function) == 1);

    host.MemoryWrite32(function, 0xE3A00002); // mov r0,#2
    host.InvalidateGuestCode(function, sizeof(uint32_t));
    assert(host.RunFunction(function) == 2);

    puts("Pending JIT invalidation check OK: modified guest code was recompiled on the next RunFunction");
}

static void SyncAbiCheck(DynarmicHost& host) {
    using namespace std::chrono_literals;
    auto& manager = host.GetThunkManager();
    auto provider = [&](const char* name) {
        const uint32_t address = manager.FindProvider(name, ThunkManager::ProviderKind::Function);
        assert(address);
        return address;
    };
    auto call = [&](uint32_t function, std::initializer_list<uint32_t> args = {}) {
        return host.RunFunction(function, std::vector<uint32_t>(args));
    };

    const uint32_t errno_fn = provider("__errno");
    const uint32_t syscall_fn = provider("syscall");
    const uint32_t ioctl_fn = provider("ioctl");
    const uint32_t sem_init = provider("sem_init");
    const uint32_t sem_destroy = provider("sem_destroy");
    const uint32_t sem_wait = provider("sem_wait");
    const uint32_t sem_trywait = provider("sem_trywait");
    const uint32_t sem_post = provider("sem_post");
    const uint32_t sem_getvalue = provider("sem_getvalue");
    const uint32_t sem_close = provider("sem_close");
    const uint32_t sem_unlink = provider("sem_unlink");
    const uint32_t mutex_init = provider("pthread_mutex_init");
    const uint32_t mutex_destroy = provider("pthread_mutex_destroy");
    const uint32_t mutex_lock = provider("pthread_mutex_lock");
    const uint32_t mutex_unlock = provider("pthread_mutex_unlock");
    const uint32_t cond_init = provider("pthread_cond_init");
    const uint32_t cond_destroy = provider("pthread_cond_destroy");
    const uint32_t cond_timedwait = provider("pthread_cond_timedwait");
    const uint32_t cond_signal = provider("pthread_cond_signal");

    const uint32_t main_errno = call(errno_fn);
    assert(main_errno >= 0x1000 && main_errno < 0x2000 && (main_errno & 3u) == 0);
    assert(call(errno_fn) == main_errno);
    assert(call(syscall_fn, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);

    constexpr uint32_t kBionicSemValueMax = 0x3fffffffu;
    const uint32_t sem = host.GuestAlloc(4, 4);
    const uint32_t max_sem = host.GuestAlloc(4, 4);
    const uint32_t value = host.GuestAlloc(4, 4);
    assert(sem && max_sem && value);
    assert(call(sem_init, {sem, 0, 0}) == 0);
    assert(host.MemoryRead32(main_errno) == ENOSYS); // successful POSIX calls do not clear errno
    assert(call(sem_trywait, {sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == EAGAIN);
    assert(call(sem_post, {sem}) == 0 && call(sem_trywait, {sem}) == 0);
    assert(call(sem_getvalue, {sem, value}) == 0 && host.MemoryRead32(value) == 0);
    assert(call(sem_init, {max_sem, 0, kBionicSemValueMax + 1}) == UINT32_MAX &&
           host.MemoryRead32(main_errno) == EINVAL);
    assert(call(sem_init, {max_sem, 1, 0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);
    assert(call(sem_init, {max_sem, 0, kBionicSemValueMax}) == 0);
    assert(call(sem_post, {max_sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == EOVERFLOW);
    assert(call(sem_getvalue, {max_sem, value}) == 0 && host.MemoryRead32(value) == kBionicSemValueMax);
    assert(call(sem_wait, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == EINVAL);
    assert(call(sem_getvalue, {sem, UINT32_MAX}) == UINT32_MAX && host.MemoryRead32(main_errno) == EFAULT);
    assert(call(sem_close, {sem}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);
    assert(call(sem_unlink, {0}) == UINT32_MAX && host.MemoryRead32(main_errno) == ENOSYS);

    // Two guest CPU contexts must expose independent, stable errno cells.
    std::barrier rendezvous(3);
    std::array<uint32_t, 2> thread_errno{};
    std::array<uint32_t, 2> thread_error{};
    std::thread first([&] {
        thread_errno[0] = call(errno_fn);
        rendezvous.arrive_and_wait();
        assert(call(syscall_fn, {0}) == UINT32_MAX);
        thread_error[0] = host.MemoryRead32(thread_errno[0]);
        rendezvous.arrive_and_wait();
    });
    std::thread second([&] {
        thread_errno[1] = call(errno_fn);
        rendezvous.arrive_and_wait();
        assert(call(ioctl_fn, {0, 0, 0}) == UINT32_MAX);
        thread_error[1] = host.MemoryRead32(thread_errno[1]);
        rendezvous.arrive_and_wait();
    });
    host.MemoryWrite32(main_errno, EDOM);
    rendezvous.arrive_and_wait();
    assert(thread_errno[0] && thread_errno[1] && thread_errno[0] != thread_errno[1] &&
           thread_errno[0] != main_errno && thread_errno[1] != main_errno);
    rendezvous.arrive_and_wait();
    first.join();
    second.join();
    assert(thread_error[0] == ENOSYS && thread_error[1] == ENOTTY && host.MemoryRead32(main_errno) == EDOM);

    const uint32_t mutex = host.GuestAlloc(4, 4);
    const uint32_t cond = host.GuestAlloc(4, 4);
    const uint32_t timeout = host.GuestAlloc(8, 4);
    assert(mutex && cond && timeout);
    assert(call(mutex_init, {mutex, 0}) == 0 && call(cond_init, {cond, 0}) == 0);
    host.MemoryWrite32(main_errno, ERANGE);

    auto timed_wait = [&](int32_t seconds, int32_t nanoseconds) {
        host.MemoryWrite32(timeout, static_cast<uint32_t>(seconds));
        host.MemoryWrite32(timeout + 4, static_cast<uint32_t>(nanoseconds));
        assert(call(mutex_lock, {mutex}) == 0);
        const auto start = std::chrono::steady_clock::now();
        const uint32_t result = call(cond_timedwait, {cond, mutex, timeout});
        const auto elapsed = std::chrono::steady_clock::now() - start;
        assert(call(mutex_unlock, {mutex}) == 0);
        return std::pair{result, elapsed};
    };
    auto negative = timed_wait(-1, 0);
    assert(negative.first == ETIMEDOUT && negative.second < 100ms);
    assert(timed_wait(0, -1).first == EINVAL);
    assert(timed_wait(0, 1000000000).first == EINVAL);
    assert(call(mutex_lock, {mutex}) == 0);
    assert(call(cond_timedwait, {cond, mutex, timeout + 1}) == EINVAL);
    assert(call(cond_timedwait, {cond, mutex, UINT32_MAX - 3}) == EINVAL);
    assert(call(mutex_unlock, {mutex}) == 0);

    auto signal_after = [&](uint32_t timeout_address) {
        assert(call(mutex_lock, {mutex}) == 0);
        std::thread signaler([&] {
            assert(call(mutex_lock, {mutex}) == 0);
            assert(call(cond_signal, {cond}) == 0);
            assert(call(mutex_unlock, {mutex}) == 0);
        });
        const uint32_t result = call(cond_timedwait, {cond, mutex, timeout_address});
        assert(call(mutex_unlock, {mutex}) == 0);
        signaler.join();
        return result;
    };
    const auto future = std::chrono::system_clock::now() + 2s;
    const auto future_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(future.time_since_epoch()).count();
    host.MemoryWrite32(timeout, static_cast<uint32_t>(future_ns / 1000000000LL));
    host.MemoryWrite32(timeout + 4, static_cast<uint32_t>(future_ns % 1000000000LL));
    assert(signal_after(timeout) == 0);
    assert(signal_after(0) == 0); // Bionic API 26 treats a null abstime as an indefinite wait.
    assert(host.MemoryRead32(main_errno) == ERANGE); // pthread APIs return errors directly.

    assert(call(cond_destroy, {cond}) == 0 && call(mutex_destroy, {mutex}) == 0);
    assert(call(sem_destroy, {sem}) == 0 && call(sem_destroy, {max_sem}) == 0);
    puts("Sync ABI checks OK: TLS errno isolation, POSIX sem errors/limits, signed ARM32 timespec and cond waits");
    fflush(stdout);
}

static void PropertySetAccelerationCheck(DynarmicHost& host) {
    assert(InstallTelltalePropertySetAddCallbackAcceleration(host));
    assert(InstallTelltaleGetKeyInfoAcceleration(host));

    const uint32_t add_callback =
        host.FindSymbol("_ZN11PropertySet15AddCallbackBaseERK6SymbolP12FunctionBase");
    const uint32_t key_callbacks_destructor =
        host.FindSymbol("_ZN11PropertySet12KeyCallbacksD2Ev");
    const uint32_t get_key_info = host.FindSymbol(
        "_ZN11PropertySet10GetKeyInfoERK6SymbolRPNS_7KeyInfoERPS_NS_15GetKeyInfoFlagsE");
    const uint32_t get_handle_object_pointer = host.FindSymbol(
        "_ZN16HandleObjectInfo22GetHandleObjectPointerEv");
    assert(add_callback && key_callbacks_destructor && get_key_info &&
           get_handle_object_pointer);
    const uint32_t frame_literal = get_handle_object_pointer + 0xF0u;
    const uint32_t frame_got =
        get_handle_object_pointer + 0x10u + 0x00AE0F70u;

    // Four maximum-size indexes exactly fill the aggregate 262144-node cache;
    // building the fifth must evict the first four before allocating. All five
    // PropertySets deliberately share one valid guest list, keeping this
    // black-box budget regression compact in guest memory.
    constexpr uint32_t budget_node_count = 65536;
    constexpr uint32_t budget_set_count = 5;
    constexpr uint32_t budget_node_size = 0x18;
    const uint32_t budget_property_sets =
        host.GuestAlloc(budget_set_count * 0x50u, 8);
    const uint32_t budget_nodes =
        host.GuestAlloc(budget_node_count * budget_node_size, 8);
    const uint32_t budget_symbols = host.GuestAlloc(16, 8);
    const uint32_t budget_callbacks =
        host.GuestAlloc((budget_set_count + 1u) * 8u, 4);
    assert(budget_property_sets && budget_nodes && budget_symbols &&
           budget_callbacks);
    memset(host.GetGuestMemoryBase() + budget_property_sets, 0,
           budget_set_count * 0x50u);
    memset(host.GetGuestMemoryBase() + budget_nodes, 0,
           budget_node_count * budget_node_size);
    memset(host.GetGuestMemoryBase() + budget_callbacks, 0,
           (budget_set_count + 1u) * 8u);

    for (uint32_t i = 0; i < budget_node_count; ++i) {
        const uint32_t node = budget_nodes + i * budget_node_size;
        host.MemoryWrite32(node + 0x00,
                           i ? node - budget_node_size : 0);
        host.MemoryWrite32(node + 0x04,
                           i + 1u < budget_node_count
                               ? node + budget_node_size
                               : 0);
        host.MemoryWrite32(node + 0x08, 0x81000000u + i);
        host.MemoryWrite32(node + 0x0C, 0x1A2B3C4Du);
    }
    const uint32_t budget_tail =
        budget_nodes + (budget_node_count - 1u) * budget_node_size;
    for (uint32_t i = 0; i < budget_set_count; ++i) {
        const uint32_t set = budget_property_sets + i * 0x50u;
        host.MemoryWrite32(set + 0x0C, budget_node_count);
        host.MemoryWrite32(set + 0x10, budget_nodes);
        host.MemoryWrite32(set + 0x14, budget_tail);
    }
    host.MemoryWrite32(budget_symbols, 0x81000000u);
    host.MemoryWrite32(budget_symbols + 4, 0x1A2B3C4Du);
    for (uint32_t i = 0; i < budget_set_count; ++i) {
        const uint32_t set = budget_property_sets + i * 0x50u;
        const uint32_t callback = budget_callbacks + i * 8u;
        assert(host.RunFunction(add_callback,
                                {set, budget_symbols, callback}) == 1);
        assert(host.MemoryRead32(budget_nodes + 0x14) == callback);
    }

    // Position 12345 is not one of a fresh 65536-node generation's six
    // witnesses (0, 65535, 0, 16385, 32770, 49155). If the first index was not
    // evicted, this new key looks like a miss and the fastpath would append.
    // A rebuild instead finds the authoritative existing node.
    constexpr uint32_t budget_changed_position = 12345;
    constexpr uint32_t budget_changed_key_low = 0xF00DBAADu;
    constexpr uint32_t budget_changed_key_high = 0xCAFEBABEu;
    const uint32_t budget_changed_node =
        budget_nodes + budget_changed_position * budget_node_size;
    const uint32_t budget_changed_callback =
        budget_callbacks + budget_set_count * 8u;
    assert(host.MemoryRead32(budget_changed_node + 0x14) == 0);
    host.MemoryWrite32(budget_changed_node + 0x08, budget_changed_key_low);
    host.MemoryWrite32(budget_changed_node + 0x0C, budget_changed_key_high);
    host.MemoryWrite32(budget_symbols + 8, budget_changed_key_low);
    host.MemoryWrite32(budget_symbols + 12, budget_changed_key_high);
    assert(host.RunFunction(add_callback,
                            {budget_property_sets, budget_symbols + 8,
                             budget_changed_callback}) == 1);
    assert(host.MemoryRead32(budget_property_sets + 0x0C) ==
           budget_node_count);
    assert(host.MemoryRead32(budget_property_sets + 0x14) == budget_tail);
    assert(host.MemoryRead32(budget_changed_node + 0x14) ==
           budget_changed_callback);
    assert(host.MemoryRead32(budget_changed_callback + 4) ==
           budget_changed_callback);

    constexpr uint32_t key_low = 0x55667788u;
    constexpr uint32_t key_high = 0x11223344u;
    constexpr uint32_t appended_key_low = 0x89ABCDEFu;
    constexpr uint32_t appended_key_high = 0x01234567u;
    constexpr uint32_t mutated_key_low = 0x10203040u;
    constexpr uint32_t mutated_key_high = 0x50607080u;
    const uint32_t property_set = host.GuestAlloc(0x50, 8);
    const uint32_t symbol = host.GuestAlloc(8, 8);
    const uint32_t appended_symbol = host.GuestAlloc(8, 8);
    const uint32_t key_node = host.GuestAlloc(0x18, 8);
    const uint32_t appended_key_node = host.GuestAlloc(0x18, 8);
    const uint32_t rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t outputs = host.GuestAlloc(8, 4);
    const uint32_t old_callback = host.GuestAlloc(8, 4);
    const uint32_t new_callback = host.GuestAlloc(8, 4);
    const uint32_t appended_old_callback = host.GuestAlloc(8, 4);
    const uint32_t appended_callback = host.GuestAlloc(8, 4);
    const uint32_t rebuilt_callback = host.GuestAlloc(8, 4);
    const uint32_t mutated_callback = host.GuestAlloc(8, 4);
    const uint32_t fallback_callback = host.GuestAlloc(8, 4);
    assert(property_set && symbol && appended_symbol && key_node &&
           appended_key_node && rb_node && outputs && old_callback &&
           new_callback && appended_old_callback && appended_callback &&
           rebuilt_callback && mutated_callback && fallback_callback);
    memset(host.GetGuestMemoryBase() + property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + key_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + appended_key_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + old_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + new_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + appended_old_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + appended_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + rebuilt_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + mutated_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + fallback_callback, 0, 8);
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(appended_symbol, appended_key_low);
    host.MemoryWrite32(appended_symbol + 4, appended_key_high);

    // Synthetic KeyCallbacks list: first invocation must use the native hit.
    host.MemoryWrite32(property_set + 0x0C, 1);
    host.MemoryWrite32(property_set + 0x10, key_node);
    host.MemoryWrite32(property_set + 0x14, key_node);
    host.MemoryWrite32(key_node + 0x08, key_low);
    host.MemoryWrite32(key_node + 0x0C, key_high);
    host.MemoryWrite32(key_node + 0x14, old_callback);
    host.MemoryWrite32(old_callback + 4, old_callback);
    assert(host.RunFunction(add_callback, {property_set, symbol, new_callback}) == 1);
    assert(host.MemoryRead32(key_node + 0x14) == new_callback);
    assert(host.MemoryRead32(old_callback + 4) == new_callback);
    assert(host.MemoryRead32(new_callback + 4) == old_callback);

    // The guest miss path appends a single KeyCallbacks node. Reproduce that
    // exact transition and require the cached native index to incorporate it.
    host.MemoryWrite32(key_node + 0x04, appended_key_node);
    host.MemoryWrite32(appended_key_node + 0x00, key_node);
    host.MemoryWrite32(appended_key_node + 0x08, appended_key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, appended_key_high);
    host.MemoryWrite32(appended_key_node + 0x14, appended_old_callback);
    host.MemoryWrite32(appended_old_callback + 4, appended_old_callback);
    host.MemoryWrite32(property_set + 0x0C, 2);
    host.MemoryWrite32(property_set + 0x14, appended_key_node);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             appended_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == appended_callback);
    assert(host.MemoryRead32(appended_old_callback + 4) == appended_callback);
    assert(host.MemoryRead32(appended_callback + 4) == appended_old_callback);

    // A removal is not the append-only fast transition. Give the surviving
    // node the removed node's key as well: a stale index would then update the
    // detached node, while a correct rebuild follows the authoritative list.
    host.MemoryWrite32(property_set + 0x0C, 1);
    host.MemoryWrite32(property_set + 0x10, appended_key_node);
    host.MemoryWrite32(property_set + 0x14, appended_key_node);
    host.MemoryWrite32(appended_key_node + 0x00, 0);
    host.MemoryWrite32(appended_key_node + 0x04, 0);
    host.MemoryWrite32(appended_key_node + 0x08, key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, key_high);
    assert(host.RunFunction(add_callback,
                            {property_set, symbol,
                             rebuilt_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == rebuilt_callback);
    assert(host.MemoryRead32(appended_callback + 4) == rebuilt_callback);
    assert(host.MemoryRead32(rebuilt_callback + 4) == appended_old_callback);

    // Metadata is unchanged here, so only per-node validation can notice the
    // in-place key mutation and rebuild the small-list index correctly.
    host.MemoryWrite32(appended_key_node + 0x08, mutated_key_low);
    host.MemoryWrite32(appended_key_node + 0x0C, mutated_key_high);
    host.MemoryWrite32(appended_symbol, mutated_key_low);
    host.MemoryWrite32(appended_symbol + 4, mutated_key_high);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             mutated_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == mutated_callback);
    assert(host.MemoryRead32(rebuilt_callback + 4) == mutated_callback);
    assert(host.MemoryRead32(mutated_callback + 4) == appended_old_callback);

    // An inconsistent count deliberately rejects the native scan. The exact
    // ARM32 body must still find the node and preserve the circular list.
    host.MemoryWrite32(property_set + 0x0C, 0);
    assert(host.RunFunction(add_callback,
                            {property_set, appended_symbol,
                             fallback_callback}) == 1);
    assert(host.MemoryRead32(appended_key_node + 0x14) == fallback_callback);
    assert(host.MemoryRead32(mutated_callback + 4) == fallback_callback);
    assert(host.MemoryRead32(fallback_callback + 4) == appended_old_callback);

    // A large cached generation validates only rotating witnesses. Exercise
    // the lifecycle guarantee that makes an unobserved ABA reuse safe: every
    // real KeyCallbacks removal runs D2, whose hook invalidates all indexes.
    constexpr uint32_t aba_node_count = 10;
    constexpr uint32_t aba_node_size = 0x18;
    const uint32_t aba_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t aba_nodes =
        host.GuestAlloc(aba_node_count * aba_node_size, 8);
    const uint32_t aba_warm_symbol = host.GuestAlloc(8, 8);
    const uint32_t aba_reused_symbol = host.GuestAlloc(8, 8);
    const uint32_t aba_warm_callback = host.GuestAlloc(8, 4);
    const uint32_t aba_reused_callback = host.GuestAlloc(8, 4);
    assert(aba_property_set && aba_nodes && aba_warm_symbol &&
           aba_reused_symbol && aba_warm_callback && aba_reused_callback);
    memset(host.GetGuestMemoryBase() + aba_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + aba_nodes, 0,
           aba_node_count * aba_node_size);
    memset(host.GetGuestMemoryBase() + aba_warm_callback, 0, 8);
    memset(host.GetGuestMemoryBase() + aba_reused_callback, 0, 8);

    for (uint32_t i = 0; i < aba_node_count; ++i) {
        const uint32_t node = aba_nodes + i * aba_node_size;
        host.MemoryWrite32(node + 0x00,
                           i ? node - aba_node_size : 0);
        host.MemoryWrite32(node + 0x04,
                           i + 1u < aba_node_count ? node + aba_node_size : 0);
        host.MemoryWrite32(node + 0x08, 0x71000000u + i);
        host.MemoryWrite32(node + 0x0C, 0x0BAD0000u + i);
    }
    host.MemoryWrite32(aba_property_set + 0x0C, aba_node_count);
    host.MemoryWrite32(aba_property_set + 0x10, aba_nodes);
    host.MemoryWrite32(aba_property_set + 0x14,
                       aba_nodes + (aba_node_count - 1u) * aba_node_size);
    host.MemoryWrite32(aba_warm_symbol, 0x71000000u);
    host.MemoryWrite32(aba_warm_symbol + 4, 0x0BAD0000u);
    assert(host.RunFunction(add_callback,
                            {aba_property_set, aba_warm_symbol,
                             aba_warm_callback}) == 1);
    assert(host.MemoryRead32(aba_nodes + 0x14) == aba_warm_callback);
    assert(host.MemoryRead32(aba_warm_callback + 4) == aba_warm_callback);

    // Position five is deliberately absent from the first six large-list
    // witnesses. Temporarily unlink it without changing count/head/tail, run
    // its real destructor, then reuse the same address and restore the exact
    // link shape with a different key.
    const uint32_t recycled_node = aba_nodes + 5u * aba_node_size;
    const uint32_t recycled_previous = recycled_node - aba_node_size;
    const uint32_t recycled_next = recycled_node + aba_node_size;
    host.MemoryWrite32(recycled_previous + 0x04, recycled_next);
    host.MemoryWrite32(recycled_next + 0x00, recycled_previous);
    host.MemoryWrite32(recycled_node + 0x00, 0);
    host.MemoryWrite32(recycled_node + 0x04, 0);
    assert(host.MemoryRead32(recycled_node + 0x14) == 0);

    bool destructor_abi_checked = false;
    const uint32_t destructor_check = host.GetThunkManager().RegisterThunk(
        "__propertyset_test_check_keycallbacks_d2_abi",
        [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
            assert(&active == &host && active.IsJitRunning());
            assert(jit.Regs()[0] == recycled_node);
            assert((jit.Regs()[13] & 7u) == 0);
            for (uint32_t reg = 4; reg <= 8; ++reg) {
                assert(jit.Regs()[reg] == 0xC0DE0000u + reg);
            }
            destructor_abi_checked = true;
        });
    assert(destructor_check);
    std::vector<uint32_t> destructor_wrapper{0xE92D41F0u};
    Load(destructor_wrapper, 0, recycled_node);
    for (uint32_t reg = 4; reg <= 8; ++reg) {
        Load(destructor_wrapper, reg, 0xC0DE0000u + reg);
    }
    Call(destructor_wrapper, key_callbacks_destructor);
    Call(destructor_wrapper, destructor_check);
    destructor_wrapper.push_back(0xE8BD81F0u);
    assert(host.RunFunction(Install(host, destructor_wrapper)) ==
           recycled_node);
    assert(destructor_abi_checked);

    constexpr uint32_t recycled_key_low = 0xDEADC0DEu;
    constexpr uint32_t recycled_key_high = 0xFEEDBEEFu;
    memset(host.GetGuestMemoryBase() + recycled_node, 0, aba_node_size);
    host.MemoryWrite32(recycled_node + 0x00, recycled_previous);
    host.MemoryWrite32(recycled_node + 0x04, recycled_next);
    host.MemoryWrite32(recycled_node + 0x08, recycled_key_low);
    host.MemoryWrite32(recycled_node + 0x0C, recycled_key_high);
    host.MemoryWrite32(recycled_previous + 0x04, recycled_node);
    host.MemoryWrite32(recycled_next + 0x00, recycled_node);
    host.MemoryWrite32(aba_reused_symbol, recycled_key_low);
    host.MemoryWrite32(aba_reused_symbol + 4, recycled_key_high);
    assert(host.RunFunction(add_callback,
                            {aba_property_set, aba_reused_symbol,
                             aba_reused_callback}) == 1);
    assert(host.MemoryRead32(recycled_node + 0x14) ==
           aba_reused_callback);
    assert(host.MemoryRead32(aba_reused_callback + 4) ==
           aba_reused_callback);

    // Reuse the same allocation as a minimal PropertySet RB tree.
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(rb_node + 0x10, key_low);
    host.MemoryWrite32(rb_node + 0x14, key_high);
    host.MemoryWrite32(property_set + 0x30, rb_node);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 0}) == key_low);
    assert(host.MemoryRead32(outputs) == rb_node);
    assert(host.MemoryRead32(outputs + 4) == property_set);

    // The two output references may legally be the same guest word.  The
    // original stores KeyInfo first and the owning PropertySet second, so the
    // latter must be the final observable value.
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs, 0}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == property_set);

    // The fixed Handle getter literal/GOT words use direct native reads.  An
    // output alias must therefore fail closed to the original ARM32 body,
    // which still performs its legal ordered output stores.  Restore the
    // deliberately overwritten engine words immediately after each call.
    const uint32_t saved_frame_literal = host.MemoryRead32(frame_literal);
    const uint32_t saved_frame_got = host.MemoryRead32(frame_got);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(
               get_key_info,
               {property_set, symbol, frame_literal, outputs + 4, 0}) ==
           key_low);
    assert(host.MemoryRead32(frame_literal) == rb_node);
    assert(host.MemoryRead32(outputs + 4) == property_set);
    host.MemoryWrite32(frame_literal, saved_frame_literal);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, frame_got, 0}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == rb_node);
    assert(host.MemoryRead32(frame_got) == property_set);
    host.MemoryWrite32(frame_got, saved_frame_got);

    // Output references are legal aliases of the input Symbol in the guest
    // ABI. The native snapshot path rejects this case; the displaced ARM32
    // body must still finish safely and preserve its ordered output stores.
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, symbol, symbol + 4, 0}) ==
           key_low);
    assert(host.MemoryRead32(symbol) == rb_node);
    assert(host.MemoryRead32(symbol + 4) == property_set);
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);

    // A local non-empty miss is completed natively and returns null outputs.
    host.MemoryWrite32(symbol, key_low + 1u);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 0}) == key_low + 1u);
    assert(host.MemoryRead32(outputs) == 0 && host.MemoryRead32(outputs + 4) == 0);

    const uint32_t current_frame =
        host.FindSymbol("_ZN16HandleObjectInfo14smCurrentFrameE");
    const uint32_t parent_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t parent_rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t parent_handle = host.GuestAlloc(0x2C, 8);
    assert(current_frame && parent_property_set && parent_rb_node &&
           parent_handle);
    memset(host.GetGuestMemoryBase() + parent_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + parent_rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + parent_handle, 0, 0x2C);

    // Flag 2 follows an already-loaded parent HandleObjectInfo twice before
    // repeating the lookup. Both the result owner and smCurrentFrame write are
    // observable parts of the original ARM32 path.
    constexpr uint32_t parent_frame_marker = 0x13579BDFu;
    host.MemoryWrite32(symbol, key_low);
    host.MemoryWrite32(symbol + 4, key_high);
    host.MemoryWrite32(parent_rb_node + 0x10, key_low);
    host.MemoryWrite32(parent_rb_node + 0x14, key_high);
    host.MemoryWrite32(parent_property_set + 0x30, parent_rb_node);
    host.MemoryWrite32(parent_handle + 0x1C, parent_property_set);
    host.MemoryWrite32(parent_handle + 0x28, 0);
    host.MemoryWrite32(property_set + 0x30, 0);
    host.MemoryWrite32(property_set + 0x44, parent_handle);
    host.MemoryWrite32(current_frame, parent_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 2}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == parent_rb_node);
    assert(host.MemoryRead32(outputs + 4) == parent_property_set);
    assert(host.MemoryRead32(parent_handle + 0x28) == parent_frame_marker);

    // An output word may also alias a HandleObjectInfo frame stamp.  All
    // deferred reads and writes must observe the single ordered ARM32 stream;
    // the final KeyInfo store therefore replaces the intermediate stamp.
    constexpr uint32_t parent_alias_frame_marker = 0x89ABCDEFu;
    host.MemoryWrite32(parent_handle + 0x28, 0);
    host.MemoryWrite32(current_frame, parent_alias_frame_marker);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(
               get_key_info,
               {property_set, symbol, parent_handle + 0x28, outputs + 4, 2}) ==
           key_low);
    assert(host.MemoryRead32(parent_handle + 0x28) == parent_rb_node);
    assert(host.MemoryRead32(outputs + 4) == parent_property_set);

    const uint32_t nested_property_set = host.GuestAlloc(0x50, 8);
    const uint32_t nested_rb_node = host.GuestAlloc(0x18, 8);
    const uint32_t nested_list_node = host.GuestAlloc(0x0C, 4);
    const uint32_t nested_handle = host.GuestAlloc(0x2C, 8);
    assert(nested_property_set && nested_rb_node && nested_list_node &&
           nested_handle);
    memset(host.GetGuestMemoryBase() + nested_property_set, 0, 0x50);
    memset(host.GetGuestMemoryBase() + nested_rb_node, 0, 0x18);
    memset(host.GetGuestMemoryBase() + nested_list_node, 0, 0x0C);
    memset(host.GetGuestMemoryBase() + nested_handle, 0, 0x2C);

    // Flag 4 walks the circular nested-PropertySet list, resolves the loaded
    // handle twice and recursively returns the child as the owning set.
    constexpr uint32_t nested_frame_marker = 0x2468ACE0u;
    const uint32_t nested_sentinel = property_set + 0x1C;
    host.MemoryWrite32(nested_rb_node + 0x10, key_low);
    host.MemoryWrite32(nested_rb_node + 0x14, key_high);
    host.MemoryWrite32(nested_property_set + 0x30, nested_rb_node);
    host.MemoryWrite32(nested_handle + 0x1C, nested_property_set);
    host.MemoryWrite32(nested_handle + 0x28, 0);
    host.MemoryWrite32(property_set + 0x1C, nested_list_node);
    host.MemoryWrite32(property_set + 0x20, nested_list_node);
    host.MemoryWrite32(nested_list_node + 0x00, nested_sentinel);
    host.MemoryWrite32(nested_list_node + 0x04, nested_sentinel);
    host.MemoryWrite32(nested_list_node + 0x08, nested_handle);
    host.MemoryWrite32(current_frame, nested_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    assert(host.RunFunction(get_key_info,
                            {property_set, symbol, outputs, outputs + 4, 4}) ==
           key_low);
    assert(host.MemoryRead32(outputs) == nested_rb_node);
    assert(host.MemoryRead32(outputs + 4) == nested_property_set);
    assert(host.MemoryRead32(nested_handle + 0x28) == nested_frame_marker);

    // More than eight distinct deferred frame stamps promotes the exact
    // latest-value shadow from its tiny inline cache to the flat table.  Every
    // child deliberately misses, so traversal continues across all nodes and
    // the ordered writes are committed only after the full list is validated.
    constexpr uint32_t promotion_child_count = 100;
    const uint32_t promotion_root = host.GuestAlloc(0x50, 8);
    const uint32_t promotion_children =
        host.GuestAlloc(promotion_child_count * 0x50u, 8);
    const uint32_t promotion_nodes =
        host.GuestAlloc(promotion_child_count * 0x0Cu, 4);
    const uint32_t promotion_handles =
        host.GuestAlloc(promotion_child_count * 0x2Cu, 8);
    assert(promotion_root && promotion_children && promotion_nodes &&
           promotion_handles);
    memset(host.GetGuestMemoryBase() + promotion_root, 0, 0x50);
    memset(host.GetGuestMemoryBase() + promotion_children, 0,
           promotion_child_count * 0x50u);
    memset(host.GetGuestMemoryBase() + promotion_nodes, 0,
           promotion_child_count * 0x0Cu);
    memset(host.GetGuestMemoryBase() + promotion_handles, 0,
           promotion_child_count * 0x2Cu);

    const uint32_t promotion_sentinel = promotion_root + 0x1C;
    host.MemoryWrite32(promotion_root + 0x1C, promotion_nodes);
    host.MemoryWrite32(
        promotion_root + 0x20,
        promotion_nodes + (promotion_child_count - 1u) * 0x0Cu);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        const uint32_t child = promotion_children + index * 0x50u;
        const uint32_t child_sentinel = child + 0x1Cu;
        const uint32_t node = promotion_nodes + index * 0x0Cu;
        const uint32_t handle = promotion_handles + index * 0x2Cu;
        host.MemoryWrite32(child + 0x1C, child_sentinel);
        host.MemoryWrite32(child + 0x20, child_sentinel);
        host.MemoryWrite32(node + 0x00,
                           index + 1u < promotion_child_count
                               ? node + 0x0Cu
                               : promotion_sentinel);
        host.MemoryWrite32(node + 0x04,
                           index ? node - 0x0Cu : promotion_sentinel);
        host.MemoryWrite32(node + 0x08, handle);
        host.MemoryWrite32(handle + 0x1C, child);
    }
    constexpr uint32_t promotion_frame_marker = 0x55AA7711u;
    host.MemoryWrite32(current_frame, promotion_frame_marker);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info,
                     {promotion_root, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 &&
           host.MemoryRead32(outputs + 4) == 0);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        assert(host.MemoryRead32(promotion_handles + index * 0x2Cu + 0x28) ==
               promotion_frame_marker);
    }

    // A second promoted call must get a fresh TLS generation and must not see
    // any address/value pair left by the previous lease.  One hundred children
    // also force the ordered log beyond its inline storage.
    constexpr uint32_t promotion_frame_marker_2 = 0xAA558822u;
    host.MemoryWrite32(current_frame, promotion_frame_marker_2);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info,
                     {promotion_root, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 &&
           host.MemoryRead32(outputs + 4) == 0);
    for (uint32_t index = 0; index < promotion_child_count; ++index) {
        assert(host.MemoryRead32(promotion_handles + index * 0x2Cu + 0x28) ==
               promotion_frame_marker_2);
    }

    // The native flag-4 path also handles a valid empty nested list.
    host.MemoryWrite32(property_set + 0x30, 0);
    host.MemoryWrite32(property_set + 0x1C, property_set + 0x1C);
    host.MemoryWrite32(property_set + 0x20, property_set + 0x1C);
    host.MemoryWrite32(outputs, 0xA5A5A5A5u);
    host.MemoryWrite32(outputs + 4, 0xA5A5A5A5u);
    host.RunFunction(get_key_info, {property_set, symbol, outputs, outputs + 4, 4});
    assert(host.MemoryRead32(outputs) == 0 && host.MemoryRead32(outputs + 4) == 0);

    puts("PropertySet acceleration checks OK: callback index generations, "
         "parent/nested traversal, current-frame writes and exact ARM32 fallback");
    fflush(stdout);
}

static bool GuestRangeCheck() {
    struct RangeCase { size_t arena; uint32_t address; size_t length; bool valid; };
    constexpr size_t full_arena = size_t{1} << 32;
    const RangeCase cases[] = {
        {0x1000, 0, 0, true}, {0x1000, 0, 1, false},
        {0x1000, 0x1000, 0, true}, {0x1000, 0x1000, 1, false},
        {0x1000, 0xFFF, 1, true}, {0x1000, 0xFFF, 2, false},
        {0x1000, 0x1001, 0, false},
        {full_arena, UINT32_MAX, 1, true}, {full_arena, UINT32_MAX, 2, false},
        {full_arena, UINT32_MAX, SIZE_MAX, false}, {full_arena, 1, SIZE_MAX, false},
        {0x80000000u, 0x80000000u, 0, true}, {0x80000000u, 0x80000000u, 1, false},
    };
    for (const auto& test : cases) {
        if (GuestRangeValid(test.arena, test.address, test.length) != test.valid) {
            fprintf(stderr, "FAIL guest span: arena=%zu address=%u length=%zu expected=%d\n",
                    test.arena, test.address, test.length, test.valid);
            return false;
        }
    }
    puts("Guest range checks OK: 13 cases, including zero length, arena end and SIZE_MAX overflow");
    return true;
}

static bool EglDestroyFailureCheck(DynarmicHost& host) {
    auto call = [&](const char* name, std::vector<uint32_t> args = {}) {
        const uint32_t fn = host.GetThunkManager().FindProvider(name, ThunkManager::ProviderKind::Function);
        assert(fn);
        return host.RunFunction(fn, args);
    };
    // Use a real off-screen surface. Current-object queries register the native
    // objects in the production handle tables without a window or game Activity.
    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    if (!eglInitialize(display, nullptr, nullptr)) {
        fprintf(stderr, "FAIL EGL initialization: 0x%x\n", eglGetError());
        return false;
    }
    const EGLint attributes[] = {EGL_SURFACE_TYPE, EGL_PBUFFER_BIT,
        EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT, EGL_NONE};
    EGLConfig config{};
    EGLint count = 0;
    assert(eglChooseConfig(display, attributes, &config, 1, &count) && count == 1);
    const EGLint context_attributes[] = {EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE};
    const EGLint surface_attributes[] = {EGL_WIDTH, 16, EGL_HEIGHT, 16, EGL_NONE};
    EGLContext context = eglCreateContext(display, config, EGL_NO_CONTEXT, context_attributes);
    EGLSurface surface = eglCreatePbufferSurface(display, config, surface_attributes);
    assert(context != EGL_NO_CONTEXT && surface != EGL_NO_SURFACE);
    assert(eglMakeCurrent(display, surface, surface, context));
    const uint32_t guest_display = call("eglGetCurrentDisplay");
    const uint32_t guest_context = call("eglGetCurrentContext");
    const uint32_t guest_surface = call("eglGetCurrentSurface", {EGL_DRAW});
    assert(guest_display && guest_context && guest_surface);
    assert(call("eglMakeCurrent", {guest_display, 0, 0, 0}) == EGL_TRUE);

    // A bad display must fail without losing either still-live guest handle.
    assert(call("eglDestroyContext", {0, guest_context}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_DISPLAY);
    assert(call("eglDestroySurface", {0, guest_surface}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_DISPLAY);
    const bool context_retry = call("eglDestroyContext", {guest_display, guest_context}) == EGL_TRUE;
    const bool surface_retry = call("eglDestroySurface", {guest_display, guest_surface}) == EGL_TRUE;
    if (!context_retry || !surface_retry) {
        fprintf(stderr, "FAIL EGL destroy retry: context=%d surface=%d\n", context_retry, surface_retry);
        return false;
    }
    assert(call("eglDestroyContext", {guest_display, guest_context}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_CONTEXT);
    assert(call("eglDestroySurface", {guest_display, guest_surface}) == EGL_FALSE);
    assert(call("eglGetError") == EGL_BAD_SURFACE);
    assert(call("eglTerminate", {guest_display}) == EGL_TRUE);
    assert(eglReleaseThread());
    puts("EGL destroy checks OK: failed destroy preserves handles, retry succeeds, successful destroy removes handles");
    return true;
}

int main(int argc, char** argv) {
    if (argc == 2 && !strcmp(argv[1], "--guest-range-only")) return GuestRangeCheck() ? 0 : 1;
    DynarmicHost host;
    const bool initialized = host.Initialize();
    assert(initialized);
    if (argc == 2 && !strcmp(argv[1], "--egl-destroy-only")) return EglDestroyFailureCheck(host) ? 0 : 1;
    if (argc == 2 && (!strcmp(argv[1],"--audio-only") || !strcmp(argv[1],"--audio-no-pump")))
        return AudioPumpCheck(host,!strcmp(argv[1],"--audio-no-pump")) ? 0 : 1;
    if (!GuestRangeCheck() || !EglDestroyFailureCheck(host)) return 1;
    PendingInvalidationCheck(host);
    AeabiMemoryCheck(host);
    const bool refused_initializers = !host.RunModuleInitializers();
    assert(refused_initializers); // no load-group audit means no initializer execution
    auto& manager = host.GetThunkManager();
    const uint32_t qsort = manager.FindProvider("qsort", ThunkManager::ProviderKind::Function, "LIBC", "libc.so");
    const uint32_t memcmp_fn = manager.FindProvider("memcmp", ThunkManager::ProviderKind::Function);
    assert(qsort && memcmp_fn); // LibcAbiSelfCheck failure prevents these registrations.
    SyncAbiCheck(host);

    bool returned = false, thumb_caller = false, bad_stack = false;
    uint32_t saved_sp = 0;
    size_t comparisons = 0;
    const uint32_t enter = manager.RegisterThunk("__qsort_test_enter", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        assert(active.IsJitRunning());
        saved_sp = jit.Regs()[13];
        assert((saved_sp & 7) == 0);
        for (unsigned i = 4; i <= 11; ++i) jit.Regs()[i] = 0xA000u + i;
        for (unsigned i = 16; i < 32; ++i) jit.ExtRegs()[i] = 0x5A000000u + i;
        if (bad_stack) jit.Regs()[13] += 4;
    });
    const uint32_t leave = manager.RegisterThunk("__qsort_test_leave", [&](Dynarmic::A32::Jit& jit, DynarmicHost&) {
        assert(jit.Regs()[13] == saved_sp);
        assert(bool(jit.Regs()[14] & 1) == thumb_caller);
        for (unsigned i = thumb_caller ? 5 : 4; i <= 11; ++i) assert(jit.Regs()[i] == 0xA000u + i);
        for (unsigned i = 16; i < 32; ++i) assert(jit.ExtRegs()[i] == 0x5A000000u + i);
        returned = true;
    });
    const uint32_t trace = manager.RegisterThunk("__qsort_test_compare", [&](Dynarmic::A32::Jit& jit, DynarmicHost& active) {
        assert(active.IsJitRunning() && (jit.Regs()[13] & 7) == 0);
        ++comparisons;
    });

    auto wrapper = [&](uint32_t target) {
        std::vector<uint32_t> code{0xE92D5FF0}; // push r4-r11,ip,lr (40 bytes)
        Call(code, enter);
        Call(code, target);
        Call(code, leave);
        code.insert(code.end(), {0xE8BD5FF0, 0xE3A0005A, 0xE12FFF1E}); // restore; mov r0,#90; bx lr
        return Install(host, code);
    };
    const uint32_t caller = wrapper(qsort);
    std::vector<uint16_t> thumb_code{0xB510}; // push r4,lr
    ThumbCall(thumb_code, enter);
    ThumbCall(thumb_code, qsort);
    ThumbCall(thumb_code, leave);
    thumb_code.insert(thumb_code.end(), {0x205A, 0xBD10}); // movs r0,#90; pop r4,pc
    const uint32_t thumb_wrapper = Install(host, thumb_code) | 1;

    std::vector<uint32_t> compare_code{0xE92D4010}; // push r4,lr
    Call(compare_code, trace);
    compare_code.insert(compare_code.end(), {
        0xE5900000, 0xE5911000, 0xE1500001, // ldr r0,[r0]; ldr r1,[r1]; cmp r0,r1
        0xE3A00000, 0xB3A00102, 0xC3E00102, // 0, INT_MIN if lt, INT_MAX if gt
        0xE8BD4010, 0xE12FFF1E});
    const uint32_t compare = Install(host, compare_code);
    const uint32_t thumb_compare = Install(host, std::vector<uint16_t>{
        0x6800, 0x6809, 0x4288, 0xDB03, 0xDC05, 0x2000, 0x4770, 0xBF00,
        0x2000, 0x43C0, 0x4770, 0x2001, 0x4770, 0xBF00}) | 1;
    const uint32_t fault_compare = Install(host, std::vector<uint32_t>{0xE7FEDEFF, 0xE12FFF1E});

    const uint32_t storage = host.GuestAlloc(4096, 8), base = storage + 9; // unaligned input plus canaries
    assert(storage);
    auto invoke = [&](uint32_t function, uint32_t address, uint32_t count, uint32_t size, uint32_t cmp, bool success) {
        returned = false;
        thumb_caller = bool(function & 1);
        const uint32_t result = host.RunFunction(function, {address, count, size, cmp});
        assert(returned == success && !host.IsJitRunning());
        if (success) assert(result == 90);
        const size_t before_drain = comparisons;
        host.DrainDeferred();
        assert(comparisons == before_drain); // comparator work must never be deferred
    };
    auto numbers = [&](std::vector<int32_t> values, uint32_t cmp, uint32_t function) {
        memset(host.GetGuestMemoryBase() + storage, 0xA5, 4096);
        memcpy(host.GetGuestMemoryBase() + base, values.data(), values.size() * 4);
        invoke(function, base, values.size(), 4, cmp, true);
        std::sort(values.begin(), values.end());
        assert(memcmp(host.GetGuestMemoryBase() + base, values.data(), values.size() * 4) == 0);
        assert(host.MemoryRead8(base - 1) == 0xA5 && host.MemoryRead8(base + values.size() * 4) == 0xA5);
    };
    for (uint32_t function : {caller, thumb_wrapper}) {
        for (uint32_t cmp : {compare, thumb_compare}) {
            numbers({5, -7, 0, 5, INT32_MIN, INT32_MAX, -7, 2}, cmp, function);
            numbers({-4, -3, -2, -1, 0, 1, 2}, cmp, function);
            numbers({9, 8, 7, 6, 5, 4, 3, 2, 1}, cmp, function);
            numbers({7, 7, 7, 7, 7}, cmp, function);
            for (uint32_t count = 2; count < 65; ++count) {
                std::vector<int32_t> values(count);
                for (uint32_t i = 0; i < count; ++i) values[i] = static_cast<int32_t>((i * 1103515245u + count * 12345u) % 37) - 18;
                numbers(values, cmp, function);
            }
        }
    }

    // A guest comparator calls host memcmp and uses its signed result in the guest helper.
    for (uint32_t size : {1u, 3u}) {
        std::vector<uint32_t> code{0xE92D4010};
        Call(code, trace);
        code.push_back(0xE3A02000 | size); // mov r2,#size
        Call(code, memcmp_fn);
        code.insert(code.end(), {0xE8BD4010, 0xE12FFF1E});
        const uint32_t cmp = Install(host, code);
        std::vector<std::vector<uint8_t>> records;
        for (unsigned i = 0; i < 31; ++i) {
            records.emplace_back(size);
            for (uint32_t j = 0; j < size; ++j) records.back()[j] = (i * 17 + j * 7) % 13;
            memcpy(host.GetGuestMemoryBase() + base + i * size, records.back().data(), size);
        }
        host.MemoryWrite8(base - 1, 0xA5);
        host.MemoryWrite8(base + records.size() * size, 0xA5);
        invoke(caller, base, records.size(), size, cmp, true);
        std::sort(records.begin(), records.end());
        for (size_t i = 0; i < records.size(); ++i) assert(memcmp(host.GetGuestMemoryBase() + base + i * size, records[i].data(), size) == 0);
        assert(host.MemoryRead8(base - 1) == 0xA5 && host.MemoryRead8(base + records.size() * size) == 0xA5);
    }

    // Nested qsort stays on the guest stack, sorting a separate array.
    const uint32_t inner = host.GuestAlloc(16, 4);
    const std::array<int32_t, 4> inner_values{8, -2, 8, 1}, inner_sorted{-2, 1, 8, 8};
    memcpy(host.GetGuestMemoryBase() + inner, inner_values.data(), 16);
    std::vector<uint32_t> nested{0xE92D4070, 0xE1A04000, 0xE1A05001}; // push r4-r6,lr; save element pointers
    Load(nested, 0, inner); Load(nested, 1, 4); Load(nested, 2, 4); Load(nested, 3, compare);
    Call(nested, qsort);
    nested.insert(nested.end(), {0xE1A00004, 0xE1A01005});
    Call(nested, compare);
    nested.insert(nested.end(), {0xE8BD4070, 0xE12FFF1E});
    numbers({3, -8, 3, 4, 2}, Install(host, nested), caller);
    assert(memcmp(host.GetGuestMemoryBase() + inner, inner_sorted.data(), 16) == 0);

    // The same helper image works at another guest address (no absolute fixups).
    std::vector<uint8_t> relocated(kGuestQsortCode, kGuestQsortCode + sizeof(kGuestQsortCode));
    const uint32_t second_helper = Install(host, relocated) + kGuestQsortEntryOffset;
    numbers({8, 4, 2, 1, 3, 5, 6, 7}, compare, wrapper(second_helper));

    const size_t before_trivial = comparisons;
    invoke(caller, 0, 0, 0, 0, true);
    invoke(caller, base, 1, 4, compare, true);
    assert(comparisons == before_trivial);
    std::array<uint8_t, 32> unchanged;
    memset(unchanged.data(), 0xA5, unchanged.size());
    memcpy(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size());
    for (const std::array<uint32_t, 4>& args : std::vector<std::array<uint32_t, 4>>{
             {0, 2, 4, compare}, {base, 2, 0, compare}, {base, UINT32_MAX, 16, compare},
             {0xFFFFFFFCu, 2, 4, compare}, {base, 2, 4, 0}, {base, 2, 4, base & ~3u},
             {base, 2, 4, compare | 2u}}) {
        invoke(caller, args[0], args[1], args[2], args[3], false);
        assert(memcmp(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size()) == 0);
    }
    bad_stack = true;
    invoke(caller, base, 2, 4, compare, false);
    bad_stack = false;
    assert(memcmp(host.GetGuestMemoryBase() + base, unchanged.data(), unchanged.size()) == 0);
    invoke(caller, base, 2, 4, fault_compare, false);
    numbers({9, 1, 2, -1}, compare, caller); // ordinary invocation after fault restores usable context
    printf("Guest qsort checks OK: SVC redirect, ARM/Thumb, order/permutation/canaries, host thunk, nested sort, PIC, failure/context; comparisons=%zu\n", comparisons);
    fflush(stdout);

    const uint32_t scan = manager.FindProvider("sscanf", ThunkManager::ProviderKind::Function);
    const uint32_t scan_text = host.GuestAlloc(8192), scan_format = host.GuestAlloc(128), scan_out = host.GuestAlloc(256);
    assert(scan && scan_text && scan_format && scan_out);
    struct ScanCase { const char* format; const char* text; int count; const char* spaces; int value; };
    for (const ScanCase& test : std::vector<ScanCase>{
             {"MemTotal:%[ \t]%d kB", "MemTotal:  6291456 kB\n", 2, "  ", 6291456},
             {"MemFree:%[ \t]%d kB", "MemFree:\t 1234 kB", 2, "\t ", 1234},
             {"MemTotal:%[ \t]%d kB", "MemTotal:  bad", 1, "  ", 0},
             {"MemTotal:%[ \t]%d kB", "MemTotal:7 kB", 0, "", 0},
             {"MemTotal:%[ \t]%d kB", "", EOF, "", 0},
             {"%d", "23", EOF, "", 0}}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), test.text);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), test.format);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, scan_out + 8, scan_out + 128}));
        assert(count == test.count);
        if (count >= 1) assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_out + 8), test.spaces) == 0);
        else assert(host.MemoryRead32(scan_out + 8) == 0xA5A5A5A5);
        assert(host.MemoryRead32(scan_out + 128) == (count >= 2 ? static_cast<uint32_t>(test.value) : 0xA5A5A5A5));
        assert(host.MemoryRead32(scan_out + 4) == 0xA5A5A5A5 && host.MemoryRead32(scan_out + 132) == 0xA5A5A5A5);
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), "MemTotal:  42 kB");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "MemTotal:%[ \t]%d kB");
    const uint32_t invalid_scan = host.RunFunction(scan, {scan_text, scan_format, 0xFFFFFFFFu, scan_out + 128});
    assert(invalid_scan == UINT32_MAX && host.MemoryRead32(scan_out + 128) == 0xA5A5A5A5);
    puts("Meminfo sscanf checks OK: exact formats, two typed outputs, partial/EOF, unsupported format, bounds/canaries");
    fflush(stdout);
    struct UrlCase { const char* format; const char* input; int count; const char* outputs[3]; };
    const uint32_t url_outputs[] = {scan_out + 8, scan_out + 80, scan_out + 160};
    for (const UrlCase& test : std::vector<UrlCase>{
             {"%15[^:]:%[^\n]", "file:assets/game.lua", 2, {"file", "assets/game.lua", ""}},
             {"%15[^\n:]://%[^\n/?]%[^\n]", "https://example.invalid/path?q=1", 3, {"https", "example.invalid", "/path?q=1"}},
             {"%[^\n/?]%[^\n]", "example.invalid/path", 2, {"example.invalid", "/path", ""}},
             {"%15[^\n:]://%[^\n/?]%[^\n]", "http://example.invalid", 2, {"http", "example.invalid", ""}},
             {"%15[^:]:%[^\n]", "abcdefghijklmnop:rest", 1, {"abcdefghijklmno", "", ""}},
             {"%[^\n/?]%[^\n]", "", EOF, {"", "", ""}}}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), test.input);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), test.format);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, url_outputs[0], url_outputs[1], url_outputs[2]}));
        assert(count == test.count);
        for (int i = 0; i < 3; ++i) {
            if (i < count) {
                assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + url_outputs[i]), test.outputs[i]) == 0);
                assert(host.MemoryRead8(url_outputs[i] + strlen(test.outputs[i]) + 1) == 0xA5);
            } else assert(host.MemoryRead32(url_outputs[i]) == 0xA5A5A5A5);
        }
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), "https://example.invalid/p");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "%15[^\n:]://%[^\n/?]%[^\n]");
    const uint32_t bad_third = host.RunFunction(scan, {scan_text, scan_format, url_outputs[0], url_outputs[1], UINT32_MAX});
    assert(bad_third == UINT32_MAX && host.MemoryRead32(url_outputs[0]) == 0xA5A5A5A5 && host.MemoryRead32(url_outputs[1]) == 0xA5A5A5A5);
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_format), "[%*45[0123456789abcdefABCDEF:.]%c");
    for (const char* value : {"[::1]", "example.invalid", ""}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + scan_text), value);
        memset(host.GetGuestMemoryBase() + scan_out, 0xA5, 256);
        const int32_t count = static_cast<int32_t>(host.RunFunction(scan, {scan_text, scan_format, url_outputs[0]}));
        const int32_t expected = value[0] == '[' ? 1 : value[0] ? 0 : EOF;
        assert(count == expected && host.MemoryRead8(url_outputs[0] + 1) == 0xA5);
        assert(host.MemoryRead8(url_outputs[0]) == (count == 1 ? ']' : 0xA5)); // %c must not append a NUL
    }
    puts("URL sscanf checks OK: exact scansets, width15, stack output, suppressed IPv6 probe/%c, partial/EOF, bounds/canaries; no network used");
    fflush(stdout);
    const uint32_t print = manager.FindProvider("vsnprintf", ThunkManager::ProviderKind::Function);
    const uint32_t print_format = host.GuestAlloc(128), print_args = host.GuestAlloc(64, 8), print_text = host.GuestAlloc(128), print_out = host.GuestAlloc(256);
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%s:%04x");
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_text), "bridge");
    host.MemoryWrite32(print_args, print_text); host.MemoryWrite32(print_args + 4, 42);
    const uint32_t printed = host.RunFunction(print, {print_out, 64, print_format, print_args});
    printf("Guest vsnprintf: count=%u text='%s' (expected 11 'bridge:002a')\n", printed, host.GetGuestMemoryBase() + print_out);
    fflush(stdout);
    assert(printed == 11 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "bridge:002a") == 0);
    const uint32_t measured = host.RunFunction(print, {0, 0, print_format, print_args});
    assert(measured == 11);
    const uint32_t truncated = host.RunFunction(print, {print_out, 8, print_format, print_args});
    assert(truncated == 11 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "bridge:") == 0);
    const uint32_t snprintf_fn = manager.FindProvider("snprintf", ThunkManager::ProviderKind::Function);
    const uint32_t measure_registers = host.RunFunction(snprintf_fn, {0, 0, print_format, print_text, 42});
    assert(measure_registers == 11);
    returned = false; thumb_caller = false;
    const uint32_t aligned_call = host.RunFunction(caller, {base, 2, 4, compare, 0}); // odd stack-word count still needs SP % 8 == 0
    assert(aligned_call == 90 && returned);
    auto print_case = [&](const char* format, const char* expected, uint32_t args) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), format);
        memset(host.GetGuestMemoryBase() + print_out, 0xA5, 256);
        const uint32_t count = host.RunFunction(print, {print_out, 128, print_format, args});
        assert(count == strlen(expected));
        assert(strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), expected) == 0);
        assert(host.MemoryRead8(print_out + strlen(expected) + 1) == 0xA5);
    };
    const double decimal = 1.25;
    uint64_t decimal_bits;
    memcpy(&decimal_bits, &decimal, 8);
    host.MemoryWrite32(print_args, static_cast<uint32_t>(-7));
    host.MemoryWrite32(print_args + 4, 42);
    host.MemoryWrite32(print_args + 8, static_cast<uint32_t>(-3));
    host.MemoryWrite64(print_args + 16, 0x1122334455667788ULL);
    host.MemoryWrite64(print_args + 24, decimal_bits);
    print_case("%+08d|%#x|%ld|%llu|%.2f", "-0000007|0x2a|-3|1234605616436508552|1.25", print_args);
    host.MemoryWrite32(print_args, static_cast<uint32_t>(-8));
    host.MemoryWrite32(print_args + 4, 2);
    host.MemoryWrite64(print_args + 8, decimal_bits);
    print_case("%*.*f", "1.25    ", print_args);
    print_case("%.2f", "1.25", print_args + 4); // absolute va_list alignment, not alignment relative to its start
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%*.*f");
    const uint32_t mixed = host.RunFunction(snprintf_fn, {print_out, 128, print_format, static_cast<uint32_t>(-8), 2, 0,
                                                         static_cast<uint32_t>(decimal_bits), static_cast<uint32_t>(decimal_bits >> 32)});
    assert(mixed == 8 && strcmp(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_out), "1.25    ") == 0);
    host.MemoryWrite32(print_args, print_out + 192); host.MemoryWrite32(print_args + 4, print_text);
    print_case("abc%n:%s", "abc:bridge", print_args);
    assert(host.MemoryRead32(print_out + 192) == 3);
    const uint32_t unterminated = static_cast<uint32_t>(host.GetGuestMemorySize() - 3);
    memcpy(host.GetGuestMemoryBase() + unterminated, "xyz", 3);
    host.MemoryWrite32(print_args, 3); host.MemoryWrite32(print_args + 4, unterminated);
    print_case("%.*s", "xyz", print_args);
    for (const char* unsupported : {"%1$d", "%ls", "%2000000u"}) {
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), unsupported);
        memset(host.GetGuestMemoryBase() + print_out, 0xA5, 256);
        const uint32_t failed = host.RunFunction(print, {print_out, 128, print_format, print_args});
        assert(failed == UINT32_MAX && host.MemoryRead32(print_out) == 0xA5A5A5A5);
    }
    strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + print_format), "%u");
    const uint32_t bad_va = host.RunFunction(print, {print_out, 128, print_format, 0xFFFFFFFFu});
    assert(bad_va == UINT32_MAX && host.MemoryRead32(print_out) == 0xA5A5A5A5);
    puts("Guest printf checks OK: varargs/GPR/stack alignment, measure/truncate, flags/width/precision, int64/double, bounded strings, %n, typed failures");
    fflush(stdout);
    // Each JIT CPU needs its own exclusive-monitor slot: unrelated LDREX/STREX
    // pairs must survive interleaving on two distinct guest addresses.
    std::barrier rendezvous(2);
    const uint32_t barrier = manager.RegisterThunk("__exclusive_test_barrier", [&](Dynarmic::A32::Jit&, DynarmicHost&) {
        rendezvous.arrive_and_wait();
    });
    std::vector<uint32_t> exclusive_code{0xE92D4070, 0xE1A04000, 0xE1945F9F}; // push; mov r4,r0; ldrex r5,[r4]
    Call(exclusive_code, barrier);
    exclusive_code.insert(exclusive_code.end(), {0xE2855001, 0xE1840F95, 0xE8BD4070, 0xE12FFF1E}); // add; strex r0,r5,[r4]; return
    const uint32_t exclusive_fn = Install(host, exclusive_code), cells = host.GuestAlloc(128, 16);
    host.MemoryWrite32(cells, 10); host.MemoryWrite32(cells + 64, 20);
    uint32_t status[2] = {UINT32_MAX, UINT32_MAX};
    std::thread first([&]() { status[0] = host.RunFunction(exclusive_fn, {cells}); });
    std::thread second([&]() { status[1] = host.RunFunction(exclusive_fn, {cells + 64}); });
    first.join(); second.join();
    printf("Exclusive slots: status=%u,%u values=%u,%u (expected 0,0 and 11,21)\n", status[0], status[1], host.MemoryRead32(cells), host.MemoryRead32(cells + 64));
    fflush(stdout);
    assert(status[0] == 0 && status[1] == 0 && host.MemoryRead32(cells) == 11 && host.MemoryRead32(cells + 64) == 21);
    if (argc > 1) {
        assert(argc == 6);
        const char* names[] = {"libSDL2.so", "libfmod.so", "libfmodstudio.so", "libGameEngine.so", "libmain.so"};
        std::vector<std::vector<uint8_t>> files;
        std::vector<GuestModuleImage> images;
        for (int i = 1; i < argc; ++i) {
            std::ifstream input(argv[i], std::ios::binary);
            assert(input.good());
            files.emplace_back(std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>());
            images.push_back({names[i - 1], files.back().data(), files.back().size()});
        }
        const bool loaded = host.LoadModulesFromMemory(images);
        assert(loaded);

        // Lifecycle hooks are part of the index's compatibility contract. A
        // separate host proves a modified D2 body fails closed without
        // contaminating the host used by the remaining integration checks.
        {
            DynarmicHost fingerprint_host;
            assert(fingerprint_host.Initialize());
            assert(fingerprint_host.LoadModulesFromMemory(images));
            const uint32_t destructor = fingerprint_host.FindSymbol(
                "_ZN11PropertySet12KeyCallbacksD2Ev");
            assert(destructor);
            fingerprint_host.MemoryWrite32(
                destructor, fingerprint_host.MemoryRead32(destructor) ^ 1u);
            fingerprint_host.InvalidateGuestCode(destructor,
                                                  sizeof(uint32_t));
            assert(!InstallTelltalePropertySetAddCallbackAcceleration(
                fingerprint_host));
        }
        puts("KeyCallbacks D2 fingerprint mismatch failed closed in an "
             "isolated host");
        fflush(stdout);

        puts("Actual five-library relocation succeeded; no game initializers invoked");
        fflush(stdout);
        PropertySetAccelerationCheck(host);
        const uint32_t mask_fn = host.FindSymbol("_ZN10StringMask11MaskCompareEPKcS1_S1_NS_8MaskModeE");
        assert(mask_fn);
        const uint32_t mask = host.GuestAlloc(128, 4), name = host.GuestAlloc(128, 4);
        strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + mask), "project_*.prop");
        for (const char* candidate : {"project_general.prop", "project.prop", "project_test.prop", "PROJECT_TEST.PROP", "nothing.prop"}) {
            strcpy(reinterpret_cast<char*>(host.GetGuestMemoryBase() + name), candidate);
            printf("Actual StringMask before: %s\n", candidate);
            fflush(stdout);
            const uint32_t result = host.RunFunction(mask_fn, {mask, name, 0, 0});
            printf("Actual StringMask result: %s -> %u\n", candidate, result);
            fflush(stdout);
            assert(result == (strchr(candidate, '_') != nullptr));
        }
    }
    return AudioPumpCheck(host,false) ? 0 : 1;
}
