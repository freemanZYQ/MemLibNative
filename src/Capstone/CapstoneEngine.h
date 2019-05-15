#pragma once
#include <Capstone/capstone.h>
using namespace System;
using namespace Collections::Generic;
using namespace Runtime::InteropServices;

namespace MemLibNative {
	namespace Capstone {
		public enum class CapstoneMode {
			Mode16 = CS_MODE_16,
			Mode32 = CS_MODE_32,
			Mode64 = CS_MODE_64
		};
		public enum class CapstoneSyntax {
			Intel = CS_OPT_SYNTAX_INTEL,
			Att = CS_OPT_SYNTAX_ATT,
			Masm = CS_OPT_SYNTAX_MASM
		};
		public value struct DisasmInstruction sealed {
			array<Byte>^ Bytes;
			String^ Mnemonic;
			String^ OpString;
			size_t Size;
			int64_t Address;
		};

		public ref class CapstoneEngine sealed : IDisposable {
			bool m_IsDisposed;
			csh m_Handle;
			CapstoneMode m_Mode;
			CapstoneSyntax m_Syntax;
		public:
			explicit CapstoneEngine(CapstoneMode mode) {
				m_IsDisposed = false;
				m_Mode = mode;
				m_Syntax = CapstoneSyntax::Intel;
				const pin_ptr<csh> handle = &m_Handle;
				cs_open(CS_ARCH_X86, static_cast<cs_mode>(mode), handle);
			}

			!CapstoneEngine() { this->~CapstoneEngine(); }

			#pragma warning(suppress: 26439) //declare function 'noexcept'
			virtual ~CapstoneEngine() {
				if (!m_IsDisposed) {
					m_IsDisposed = true;
					const pin_ptr<csh> handle = &m_Handle;
					cs_close(handle);
				}
			}

			property CapstoneMode Mode {
				CapstoneMode get() { return m_Mode; }
				void set(CapstoneMode mode) {
					m_Mode = mode;
					cs_option(m_Handle, CS_OPT_MODE, static_cast<cs_mode>(mode));
				}
			}
			property CapstoneSyntax Syntax {
				CapstoneSyntax get() { return m_Syntax; }
				void set(CapstoneSyntax syntax) {
					m_Syntax = syntax;
					cs_option(m_Handle, CS_OPT_SYNTAX, static_cast<cs_opt_value>(syntax));
				}
			}
		public:
			List<DisasmInstruction>^ Disassemble(array<Byte>^ data) {
				return Disassemble(data, 0);
			}
			List<DisasmInstruction>^ Disassemble(array<Byte>^ data, IntPtr address) {
				return Disassemble(data, address.ToInt64());
			}
			bool Disassemble(array<Byte>^ data, [Out] List<DisasmInstruction>^% instructions) {
				return Disassemble(data, 0, instructions);
			}
			bool Disassemble(array<Byte>^ data, IntPtr address, [Out] List<DisasmInstruction>^% instructions) {
				return Disassemble(data, address.ToInt64(), instructions);
			}

			DisasmInstruction DisassembleSingle(array<Byte>^ data) {
				return DisassembleSingle(data, 0);
			}
			DisasmInstruction DisassembleSingle(array<Byte>^ data, IntPtr address) {
				return DisassembleSingle(data, address.ToInt64());
			}
			bool DisassembleSingle(array<Byte>^ data, [Out] DisasmInstruction% instruction) {
				return DisassembleSingle(data, 0, instruction);
			}
			bool DisassembleSingle(array<Byte>^ data, IntPtr address, [Out] DisasmInstruction% instruction) {
				return DisassembleSingle(data, address.ToInt64(), instruction);
			}

			List<DisasmInstruction>^ Disassemble(array<Byte>^ data, const int64_t address) {
				cs_insn* insn;
				const pin_ptr<Byte> p_data = &data[0];
				const auto count = cs_disasm(m_Handle, p_data, data->Length, address, 0, &insn);
				auto results = gcnew List<DisasmInstruction>();
				for(auto i = 0; i < count; i++) {
					DisasmInstruction dinsn;
					dinsn.Size = insn[i].size;
					dinsn.Address = insn[i].address;
					dinsn.Mnemonic = gcnew String(insn[i].mnemonic);
					dinsn.OpString = gcnew String(insn[i].op_str);
					dinsn.Bytes = gcnew array<Byte>(insn[i].size);
					Marshal::Copy(IntPtr(insn[i].bytes), dinsn.Bytes, 0, insn[i].size);
					results->Add(dinsn);
				}
				return results;
			}

			bool Disassemble(array<Byte>^ data, const int64_t address, [Out] List<DisasmInstruction>^% instructions) {
				cs_insn* insn;
				const pin_ptr<Byte> p_data = &data[0];
				const auto count = cs_disasm(m_Handle, p_data, data->Length, address, 0, &insn);
				if (count <= 0) {
					instructions = nullptr;
					return false;
				}
				instructions = gcnew List<DisasmInstruction>();
				for (auto i = 0; i < count; i++) {
					if(insn[i].size <= 0) {
						instructions = nullptr;
						return false;
					}
					DisasmInstruction dinsn;
					dinsn.Size = insn[i].size;
					dinsn.Address = insn[i].address;
					dinsn.Mnemonic = gcnew String(insn[i].mnemonic);
					dinsn.OpString = gcnew String(insn[i].op_str);
					dinsn.Bytes = gcnew array<Byte>(insn[i].size);
					Marshal::Copy(IntPtr(insn[i].bytes), dinsn.Bytes, 0, insn[i].size);
					instructions->Add(dinsn);
				}
				return true;
			}

			DisasmInstruction DisassembleSingle(array<Byte>^ data, const int64_t address) {
				cs_insn* insn;
				const pin_ptr<Byte> p_data = &data[0];
				const auto count = cs_disasm(m_Handle, p_data, data->Length, address, 1, &insn);
				DisasmInstruction dinsn;
				if (count != 1)
					return dinsn;
				dinsn.Size = insn->size;
				dinsn.Address = insn->address;
				dinsn.Mnemonic = gcnew String(insn->mnemonic);
				dinsn.OpString = gcnew String(insn->op_str);
				dinsn.Bytes = gcnew array<Byte>(insn->size);
				Marshal::Copy(IntPtr(insn->bytes), dinsn.Bytes, 0, insn->size);
				return dinsn;
			}

			bool DisassembleSingle(array<Byte>^ data, const int64_t address, [Out] DisasmInstruction% instruction) {
				cs_insn* insn;
				const pin_ptr<Byte> p_data = &data[0];
				const auto count = cs_disasm(m_Handle, p_data, data->Length, address, 1, &insn);
				if (count != 1)
					return false;

				DisasmInstruction dinsn;
				dinsn.Size = insn->size;
				dinsn.Address = insn->address;
				dinsn.Mnemonic = gcnew String(insn->mnemonic);
				dinsn.OpString = gcnew String(insn->op_str);
				dinsn.Bytes = gcnew array<Byte>(insn->size);
				Marshal::Copy(IntPtr(insn->bytes), dinsn.Bytes, 0, insn->size);

				instruction = dinsn;
				return true;
			}
		};
	}
}
