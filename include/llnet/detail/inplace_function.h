/*
 * Boost Software License - Version 1.0 - August 17th, 2003
 * SG14 inplace_function — fixed-capacity type-erased callable, no heap allocation.
 */
#pragma once

#include <functional>
#include <type_traits>
#include <utility>

#ifndef LLNET_INPLACE_FUNCTION_THROW
#define LLNET_INPLACE_FUNCTION_THROW(x) throw(x)
#endif

namespace llnet::detail
{

  namespace inplace_function_detail
  {
    static constexpr size_t DefaultCapacity = 32;

    template<size_t Cap>
    union aligned_storage_helper
    {
      struct double1 { double a; };
      struct double4 { double a[4]; };
      template<class T>
      using maybe = std::conditional_t<(Cap >= sizeof(T)), T, char>;
      char real_data[Cap];
      maybe<int> a; maybe<long> b; maybe<long long> c;
      maybe<void*> d; maybe<void(*)()> e;
      maybe<double1> f; maybe<double4> g; maybe<long double> h;
    };

    template<size_t Cap, size_t Align = alignof(aligned_storage_helper<Cap>)>
    using aligned_storage_t = std::aligned_storage_t<Cap, Align>;

    template<class R, class... Args>
    struct vtable
    {
      using storage_ptr_t    = void*;
      using invoke_ptr_t     = R(*)(storage_ptr_t, Args&&...);
      using process_ptr_t    = void(*)(storage_ptr_t, storage_ptr_t);
      using destructor_ptr_t = void(*)(storage_ptr_t);

      const invoke_ptr_t     invoke_ptr;
      const process_ptr_t    copy_ptr;
      const process_ptr_t    relocate_ptr;
      const destructor_ptr_t destructor_ptr;

      explicit constexpr vtable() noexcept
        : invoke_ptr    {[](storage_ptr_t, Args&&...) -> R { LLNET_INPLACE_FUNCTION_THROW(std::bad_function_call()); }}
        , copy_ptr      {[](storage_ptr_t, storage_ptr_t) {}}
        , relocate_ptr  {[](storage_ptr_t, storage_ptr_t) {}}
        , destructor_ptr{[](storage_ptr_t) {}}
      {}

      template<class C>
      explicit constexpr vtable(std::type_identity<C>) noexcept
        : invoke_ptr    {[](storage_ptr_t s, Args&&... a) -> R { return (*static_cast<C*>(s))(static_cast<Args&&>(a)...); }}
        , copy_ptr      {[](storage_ptr_t d, storage_ptr_t s) { ::new(d) C{*static_cast<C*>(s)}; }}
        , relocate_ptr  {[](storage_ptr_t d, storage_ptr_t s) { ::new(d) C{std::move(*static_cast<C*>(s))}; static_cast<C*>(s)->~C(); }}
        , destructor_ptr{[](storage_ptr_t s) { static_cast<C*>(s)->~C(); }}
      {}

      vtable(const vtable&) = delete;
      vtable& operator=(const vtable&) = delete;
    };

    template<class R, class... Args>
    inline constexpr vtable<R, Args...> empty_vtable{};

    template<class>
    struct is_inplace_function : std::false_type {};
  }

  template<class Sig,
           size_t Capacity  = inplace_function_detail::DefaultCapacity,
           size_t Alignment = alignof(inplace_function_detail::aligned_storage_t<Capacity>)>
  class inplace_function;

  namespace inplace_function_detail
  {
    template<class Sig, size_t Cap, size_t Align>
    struct is_inplace_function<inplace_function<Sig, Cap, Align>> : std::true_type {};
  }

  template<class R, class... Args, size_t Capacity, size_t Alignment>
  class inplace_function<R(Args...), Capacity, Alignment>
  {
    using storage_t    = inplace_function_detail::aligned_storage_t<Capacity, Alignment>;
    using vtable_t     = inplace_function_detail::vtable<R, Args...>;
    using vtable_ptr_t = const vtable_t*;

    template<class, size_t, size_t>
    friend class inplace_function;

   public:
    inplace_function() noexcept
      : vtable_ptr_{&inplace_function_detail::empty_vtable<R, Args...>}
    {}

    inplace_function(std::nullptr_t) noexcept : inplace_function() {}

    template<class T,
             class C = std::decay_t<T>,
             class   = std::enable_if_t<!inplace_function_detail::is_inplace_function<C>::value>>
    inplace_function(T&& closure)
    {
      static_assert(sizeof(C) <= Capacity,   "callable too large for inplace_function capacity");
      static_assert(Alignment % alignof(C) == 0, "callable alignment incompatible");
      static const vtable_t vt{std::type_identity<C>{}};
      vtable_ptr_ = &vt;
      ::new(std::addressof(storage_)) C{std::forward<T>(closure)};
    }

    inplace_function(const inplace_function& o) : vtable_ptr_{o.vtable_ptr_}
    { vtable_ptr_->copy_ptr(std::addressof(storage_), std::addressof(o.storage_)); }

    inplace_function(inplace_function&& o) noexcept
      : vtable_ptr_{std::exchange(o.vtable_ptr_, &inplace_function_detail::empty_vtable<R, Args...>)}
    { vtable_ptr_->relocate_ptr(std::addressof(storage_), std::addressof(o.storage_)); }

    inplace_function& operator=(inplace_function o) noexcept
    {
      vtable_ptr_->destructor_ptr(std::addressof(storage_));
      vtable_ptr_ = std::exchange(o.vtable_ptr_, &inplace_function_detail::empty_vtable<R, Args...>);
      vtable_ptr_->relocate_ptr(std::addressof(storage_), std::addressof(o.storage_));
      return *this;
    }

    inplace_function& operator=(std::nullptr_t) noexcept
    {
      vtable_ptr_->destructor_ptr(std::addressof(storage_));
      vtable_ptr_ = &inplace_function_detail::empty_vtable<R, Args...>;
      return *this;
    }

    ~inplace_function() { vtable_ptr_->destructor_ptr(std::addressof(storage_)); }

    R operator()(Args... args) const
    { return vtable_ptr_->invoke_ptr(std::addressof(storage_), std::forward<Args>(args)...); }

    explicit operator bool() const noexcept
    { return vtable_ptr_ != &inplace_function_detail::empty_vtable<R, Args...>; }

    bool operator==(std::nullptr_t) const noexcept { return !operator bool(); }
    bool operator!=(std::nullptr_t) const noexcept { return  operator bool(); }

   private:
    vtable_ptr_t   vtable_ptr_;
    mutable storage_t storage_;
  };

} // namespace llnet::detail
