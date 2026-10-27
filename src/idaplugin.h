/**
 * @file idaplugin.h
 * @brief Main plugin class (plugmod_t, one instance per database).
 * @copyright (c) 2017 Avast Software, (c) 2019-2026 Gregory Morse, MIT license.
 */

#ifndef IDAPLUGIN_IDAPLUGIN_H
#define IDAPLUGIN_IDAPLUGIN_H

#include "defs.h"

namespace idaplugin {
	class GhidraDec	
		: public plugmod_t, public event_listener_t
	{
	public:
		GhidraDec();
		virtual ~GhidraDec();
		bool canDecompileInput();
		bool prepareDecompilation();
		void runSelectiveDecompilation(func_t* fnc2decomp = nullptr, bool force = false);
		/**
		 * General info used by plugin.
		 */
		RdGlobalInfo* decompInfo = nullptr;
		ea_t globalAddress = 0;

		void killDecompilation(bool bTerminate);
		void saveIdaDatabase(bool inSitu = false, const std::string& suffix = ".dec-backup");
		void generatePluginDatabase();
		bool isRelocatable();
		void runAllDecompilation();
		bool setInputPath();
		bool idaapi run(size_t arg) override;
		ssize_t idaapi on_event(ssize_t notification_code, va_list va) override;
		void onViewClose(TWidget* view);
		void init();
		void term();
		static int idaapi batchTimer(void* ud);
		bool batchStarted = false;
		bool isWordGlobal(const std::string& word, int color);
		const NameItem* getWordGlobal(const std::string& word, int color);
		bool isWordFunction(const std::string& word, int color);
		const NameItem* getWordFunction(
			const std::string& word,
			int color);
		func_t* getIdaFunction(const std::string& word, int color);
		func_t* getAddressAdjacentFunction(bool forward) const;
		bool isCurrentFunction(func_t* fnc);
		func_t* getCurrentFunction();
		bool isWordCurrentParameter(const std::string& word, int color);
		void decompileFunction(
			TWidget* cv,
			const std::string& calledFnc,
			bool force = false,
			bool forceDec = false);
		bool canMoveToPrevious() const;
		bool canMoveToNext() const;
		bool idaapi moveToPrevious();

		struct move_backward_ah_t : public action_handler_t
		{
			move_backward_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr)
				{
					return false;
				}
				pm->moveToPrevious();
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return pm != nullptr && pm->canMoveToPrevious()
						? AST_ENABLE_ALWAYS
						: AST_DISABLE;
			}
		};
		move_backward_ah_t move_backward_ah = move_backward_ah_t(this);
		const action_desc_t move_backward_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			move_backward_ah_t::actionName,
			move_backward_ah_t::actionLabel,
			&move_backward_ah,
			this,
			nullptr,
			move_backward_ah_t::actionHotkey,
			-1);
		bool idaapi moveToNext();
		struct move_forward_ah_t : public action_handler_t
		{
			move_forward_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr)
				{
					return false;
				}
				pm->moveToNext();
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return pm != nullptr && pm->canMoveToNext()
						? AST_ENABLE_ALWAYS
						: AST_DISABLE;
			}
		};


		move_forward_ah_t move_forward_ah = move_forward_ah_t(this);
		const action_desc_t move_forward_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			move_forward_ah_t::actionName,
			move_forward_ah_t::actionLabel,
			&move_forward_ah,
			this,
			nullptr,
			move_forward_ah_t::actionHotkey,
			-1);
		bool idaapi insertCurrentFunctionComment();
		struct change_fnc_comment_ah_t : public action_handler_t
		{
			change_fnc_comment_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr)
				{
					return false;
				}
				pm->insertCurrentFunctionComment();
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}
		};

		change_fnc_comment_ah_t change_fnc_comment_ah = change_fnc_comment_ah_t(this);
		const action_desc_t change_fnc_comment_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			change_fnc_comment_ah_t::actionName,
			change_fnc_comment_ah_t::actionLabel,
			&change_fnc_comment_ah,
			this,
			nullptr,
			change_fnc_comment_ah_t::actionHotkey,
			-1);
		bool idaapi changeFunctionGlobalName(TWidget* cv);
		struct change_fnc_global_name_ah_t : public action_handler_t
		{
			change_fnc_global_name_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			TWidget* view = nullptr;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr || view == nullptr)
				{
					return false;
				}
				pm->changeFunctionGlobalName(view);
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}

			void setView(TWidget* v)
			{
				view = v;
			}
		};
		bool idaapi openXrefsWindow(func_t* fnc);
		change_fnc_global_name_ah_t change_fnc_global_name_ah = change_fnc_global_name_ah_t(this);
		const action_desc_t change_fnc_global_name_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			change_fnc_global_name_ah_t::actionName,
			change_fnc_global_name_ah_t::actionLabel,
			&change_fnc_global_name_ah,
			this,
			nullptr,
			change_fnc_global_name_ah_t::actionHotkey,
			-1);
		struct open_xrefs_ah_t : public action_handler_t
		{
			open_xrefs_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			func_t* fnc = nullptr;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr || fnc == nullptr)
				{
					return false;
				}
				pm->openXrefsWindow(fnc);
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}

			void setFunction(func_t* f)
			{
				fnc = f;
			}
		};

		bool idaapi openCallsWindow(func_t* fnc);
		open_xrefs_ah_t open_xrefs_ah = open_xrefs_ah_t(this);
		const action_desc_t open_xrefs_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			open_xrefs_ah_t::actionName,
			open_xrefs_ah_t::actionLabel,
			&open_xrefs_ah,
			this,
			nullptr,
			open_xrefs_ah_t::actionHotkey,
			-1);
		struct open_calls_ah_t : public action_handler_t
		{
			open_calls_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			func_t* fnc = nullptr;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr || fnc == nullptr)
				{
					return false;
				}
				pm->openCallsWindow(fnc);
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}

			void setFunction(func_t* f)
			{
				fnc = f;
			}
		};

		open_calls_ah_t open_calls_ah = open_calls_ah_t(this);
		const action_desc_t open_calls_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			open_calls_ah_t::actionName,
			open_calls_ah_t::actionLabel,
			&open_calls_ah,
			this,
			nullptr,
			open_calls_ah_t::actionHotkey,
			-1);
		bool idaapi changeTypeDeclaration(TWidget* cv);
		struct change_fnc_type_ah_t : public action_handler_t
		{
			change_fnc_type_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			TWidget* view = nullptr;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr || view == nullptr)
				{
					return false;
				}
				pm->changeTypeDeclaration(view);
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}

			void setView(TWidget* v)
			{
				view = v;
			}
		};

		bool idaapi jumpToASM(ea_t ea);
		change_fnc_type_ah_t change_fnc_type_ah = change_fnc_type_ah_t(this);
		const action_desc_t change_fnc_type_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			change_fnc_type_ah_t::actionName,
			change_fnc_type_ah_t::actionLabel,
			&change_fnc_type_ah,
			this,
			nullptr,
			change_fnc_type_ah_t::actionHotkey,
			-1);
		struct jump_to_asm_ah_t : public action_handler_t
		{
			jump_to_asm_ah_t(GhidraDec* pm = nullptr) : action_handler_t() {
				this->pm = pm;
			}
			GhidraDec* pm;
			ea_t addr = BADADDR;
			static const char* actionName;
			static const char* actionLabel;
			static const char* actionHotkey;

			virtual int idaapi activate(action_activation_ctx_t*)
			{
				if (pm == nullptr || addr == BADADDR)
				{
					return false;
				}
				pm->jumpToASM(addr);
				return false;
			}

			virtual action_state_t idaapi update(action_update_ctx_t*)
			{
				return AST_ENABLE_ALWAYS;
			}

			void setAddress(ea_t a)
			{
				addr = a;
			}
		};

		jump_to_asm_ah_t jump_to_asm_ah = jump_to_asm_ah_t(this);
		const action_desc_t jump_to_asm_ah_desc = ACTION_DESC_LITERAL_PLUGMOD(
			jump_to_asm_ah_t::actionName,
			jump_to_asm_ah_t::actionLabel,
			&jump_to_asm_ah,
			this,
			nullptr,
			jump_to_asm_ah_t::actionHotkey,
			-1);
		static ssize_t idaapi ui_callback(void* ud, int notification_code, va_list va);
		void registerPermanentActions();

		// HT_VIEW notifications get their own listener so their codes are not
		// mixed up with HT_UI codes.
		struct view_listener_t : public event_listener_t
		{
			GhidraDec* pm = nullptr;
			ssize_t idaapi on_event(ssize_t code, va_list va) override;
		};
		view_listener_t viewListener;

		// "GhidraDec" menu: each entry runs run(arg).
		struct menu_ah_t : public action_handler_t
		{
			GhidraDec* pm = nullptr;
			size_t arg = 0;
			int idaapi activate(action_activation_ctx_t*) override
			{
				if (pm != nullptr)
					pm->run(arg);
				return 0;
			}
			action_state_t idaapi update(action_update_ctx_t*) override
			{
				return AST_ENABLE_ALWAYS;
			}
		};
		menu_ah_t menuHandlers[4];
		void registerMenu();
		void unregisterMenu();
	};

} // namespace idaplugin

#endif
