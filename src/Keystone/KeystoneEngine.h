#pragma once
#include <msclr/marshal.h>
#include <keystone/keystone.h>

using namespace System;
using namespace Runtime::InteropServices;

namespace MemLibNative {
	namespace Keystone {
		public enum class KsMode {
			Mode16 = KS_MODE_16,
			Mode32 = KS_MODE_32,
			Mode64 = KS_MODE_64,
		};

		[Flags]
		public enum class KsSyntax {
			Intel = KS_OPT_SYNTAX_INTEL,
			Att = KS_OPT_SYNTAX_ATT,
			Nasm = KS_OPT_SYNTAX_NASM,
			//Masm = KS_OPT_SYNTAX_MASM, // X86 Masm syntax - unsupported.
			Gas = KS_OPT_SYNTAX_GAS,
			Radix16 = KS_OPT_SYNTAX_RADIX16,
		};

		public ref class KeystoneEngine sealed : IDisposable {
		public:
			KeystoneEngine() : KeystoneEngine{KsMode::Mode64} {}

			explicit KeystoneEngine(KsMode mode) {
				m_IsDisposed = false;
				const auto ksmode = static_cast<ks_mode>(mode);
				const pin_ptr<ks_engine*> engine = &m_Engine;
				ks_open(KS_ARCH_X86, ksmode, engine);
				m_Syntax = KsSyntax::Intel;
			}

			!KeystoneEngine() { this->~KeystoneEngine(); }

			#pragma warning(suppress: 26439) //declare function 'noexcept'
			virtual ~KeystoneEngine() {
				if (!m_IsDisposed) {
					m_IsDisposed = true;
					ks_close(m_Engine);
				}
			}

		private:
			bool m_IsDisposed;
			ks_engine* m_Engine;
			KsSyntax m_Syntax;
		public:
			property KsSyntax Syntax
			{
				KsSyntax get() { return m_Syntax; }
				void set(KsSyntax value) {
					m_Syntax = value;
					ks_option(m_Engine, KS_OPT_SYNTAX, static_cast<size_t>(value));
				}
			}

			int GetLastError() {
				return static_cast<int>(ks_errno(m_Engine));
			}

			String^ GetLastErrorString() {
				return gcnew String(ks_strerror(ks_errno(m_Engine)));
			}

			bool Assemble(String^ source, [Out] array<Byte>^% buffer) {
				return Assemble(source, IntPtr::Zero, buffer);
			}

			bool Assemble(String^ source, const Int64 address, [Out] array<Byte>^% buffer) {
				return Assemble(source, IntPtr(address), buffer);
			}

			bool Assemble(String^ source, IntPtr address, [Out] array<Byte>^% buffer) {
				auto marshalcontext = gcnew msclr::interop::marshal_context();
				const auto marshal_source = marshalcontext->marshal_as<const char*>(source);

				unsigned char* encode;
				size_t size;
				size_t count;

				if (ks_asm(m_Engine, marshal_source, address.ToInt64(), &encode, &size, &count) != KS_ERR_OK) {
					ks_free(encode);
					return false;
				}

				buffer = gcnew array<Byte>(static_cast<int>(size));
				const pin_ptr<Byte> p_buffer = &buffer[0];
				memcpy(p_buffer, encode, size);

				ks_free(encode);
				return true;
			}

			array<Byte>^ Assemble(String^ source) {
				return Assemble(source, IntPtr::Zero);
			}

			array<Byte>^ Assemble(String^ source, const Int64 address) {
				return Assemble(source, IntPtr(address));
			}

			array<Byte>^ Assemble(String^ source, IntPtr address) {
				auto marshalcontext = gcnew msclr::interop::marshal_context();
				const auto marshal_source = marshalcontext->marshal_as<const char*>(source);

				unsigned char* encode;
				size_t size;
				size_t count;

				if (ks_asm(m_Engine, marshal_source, address.ToInt64(), &encode, &size, &count) != KS_ERR_OK) {
					ks_free(encode);
					return nullptr;
				}

				auto buffer = gcnew array<Byte>(static_cast<int>(size));
				const pin_ptr<Byte> p_buffer = &buffer[0];
				memcpy(p_buffer, encode, size);

				ks_free(encode);
				return buffer;
			}
		};
	}
}