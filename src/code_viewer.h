/**
 * @file code_viewer.h
 * @brief Module contains classes/methods dealing with decompiled code visualization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef IDAPLUGIN_CODE_VIEWER_H
#define IDAPLUGIN_CODE_VIEWER_H

#include <cstdint>
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>

#include "defs.h"

struct jobj_t;     // parsejson.hpp

namespace idaplugin {

/// @name Callbacks reacting on custom viewer.
/// @{
bool idaapi ct_keyboard(TWidget* cv, int key, int shift, void* ud);
bool idaapi ct_double(TWidget* cv, int shift, void* ud);
void idaapi ct_close(TWidget* cv, void* ud);
/// @}

void registerPermanentActions();
ssize_t idaapi ui_callback(void* ud, int notification_code, va_list va);

/// @name Desktop persistence (ui_get_widget_config / ui_create_desktop_widget).
/// The code of the shown function is kept in the database, the function and
/// the cursor go into the saved desktop, and IDA asks for the viewer again
/// when it reopens the database.
/// @{
void saveViewForDesktop(RdGlobalInfo* di);
void viewGetDesktopConfig(RdGlobalInfo* di, const TWidget* w, jobj_t* cfg);
void viewSetDesktopConfig(RdGlobalInfo* di, const TWidget* w, const jobj_t* cfg);
TWidget* viewCreateForDesktop(RdGlobalInfo* di, const char* title, const jobj_t* cfg);
/// @}

/// Title of the viewer of 'decompiledFunction': "GhidraDec: <function>".
std::string viewerTitle(const RdGlobalInfo* di);
/// Replace the viewer by one with the title of the current function, from a timer.
void scheduleViewerRetitle(RdGlobalInfo* di);

/// @name Functions working with GUI from threads.
/// @{
//int idaapi showDecompiledCode(void *ud);
/// @}

/**
 * All the handlers for our custom view.
 */
static const custom_viewer_handlers_t handlers(
		ct_keyboard, // keyboard
		nullptr,     // popup
		nullptr,     // mouse_moved
		nullptr,     // click
		ct_double,   // dblclick
		nullptr,     // current position change
		ct_close,     // close
		nullptr,     // help
		nullptr,     // adjust_place
		nullptr,
		nullptr,
		nullptr
);

/**
 * This is a structure defining execute() method which will be executed
 * by master thread through 'execute_sync()' call.
 * Its purpose is to display decompiled code in custom viewer.
 *
 * It sets plugin's tform and viewer.
 *
 * It uses current 'decompiledFunction' to get associated code from 'fnc2code'.
 *
 * The viewer keeps one stable line buffer so navigation can refresh in-place
 * without closing the widget that is currently dispatching an action.
 */
struct ShowOutput : public exec_request_t
{
	RdGlobalInfo *di;

	ShowOutput(RdGlobalInfo *i) : di(i) {}
	virtual ~ShowOutput() override {}

	virtual GHIDRADEC_EXEC_RETURN idaapi execute() override
	{
		if (!loadFunctionCode())
		{
			return 0;
		}
		saveViewForDesktop(di);

		if (di->custViewer != nullptr && di->codeViewer != nullptr)
		{
			simpleline_place_t minPlace;
			simpleline_place_t maxPlace((int)di->viewerLines.size()-1);
			set_custom_viewer_range(di->custViewer, &minPlace, &maxPlace);
			refresh_custom_viewer(di->custViewer);
			repaint_custom_viewer(di->custViewer);
			// IDA cannot rename a widget: another function gets a new viewer,
			// out of the callback that may be running in this one
			if (viewerTitle(di) != di->viewerTitle)
				scheduleViewerRetitle(di);
			return 0;
		}

		createViewer(true);
		return 0;
	}

	/**
	 * Create the viewer of 'viewerLines', titled after the function. An old
	 * viewer is replaced: the new one takes its place (a tab next to it) and the
	 * old one is closed. 'display' false leaves it undisplayed: IDA places it
	 * itself when it restores a desktop.
	 * @return The top-level widget (the code viewer, or the custom viewer).
	 */
	TWidget* createViewer(bool display)
	{
		simpleline_place_t minPlace;
		simpleline_place_t curPlace = minPlace;
		simpleline_place_t maxPlace((int)di->viewerLines.size()-1);

		const std::string title = viewerTitle(di);
		TWidget* oldTop = di->codeViewer != nullptr ? di->codeViewer : di->custViewer;
		const std::string oldTitle = di->viewerTitle;
		if (oldTop != nullptr && oldTitle == title)
		{
			// two widgets cannot have the same title
			close_widget(oldTop, 0);
			oldTop = nullptr;
		}
		di->codeViewer = nullptr;
		di->custViewer = nullptr;

		di->viewerTitle = title;
		di->custViewer = create_custom_viewer(
				title.c_str(),          // name of viewer
				&minPlace,              // first location of the viewer
				&maxPlace,              // last location of the viewer
				&curPlace,              // set current location
				nullptr,                // renderer information (can be NULL)
				&di->viewerLines,       // contents of viewer
				&handlers,              // handlers for the viewer (can be NULL)
				di,                     // handlers' user data
				nullptr                 // widget to hold viewer
		);

		int displayOptions = WOPN_DP_TAB |
				/// we want to catch ESC and use it for navigation
				WOPN_NOT_CLOSED_BY_ESC;

		qstring plainViewerEnv;
		const bool plainViewer =
			qgetenv("GHIDRADEC_PLAIN_VIEWER", &plainViewerEnv) &&
			std::string(plainViewerEnv.c_str()) != "0";

		if (!plainViewer)
		{
			di->codeViewer = create_code_viewer(di->custViewer);
			qstring sourceViewerEnv;
			if (qgetenv("GHIDRADEC_SOURCE_VIEWER", &sourceViewerEnv) &&
				std::string(sourceViewerEnv.c_str()) != "0")
				set_code_viewer_is_source(di->codeViewer);
		}
		TWidget* top = di->codeViewer != nullptr ? di->codeViewer : di->custViewer;

		if (display)
			display_widget(top, displayOptions, oldTop != nullptr ? oldTitle.c_str() : nullptr);
		if (oldTop != nullptr)
			close_widget(oldTop, 0);

		return top;
	}

	bool idaapi loadFunctionCode()
	{
		addCommentToFunctionCode();
		func_t* fnc = di->decompiledFunction;
		auto fit = di->fnc2code.find(fnc);
		if (fit == di->fnc2code.end())
		{
			return false;
		}

		std::istringstream f(fit->second.code);
		std::string line;
		di->viewerLines.clear();
		while (std::getline(f, line))
		{
			di->viewerLines.push_back(simpleline_t(line.c_str()));
		}
		if (di->viewerLines.empty())
		{
			di->viewerLines.push_back(simpleline_t(""));
		}

		return true;
	}

	void idaapi addCommentToFunctionCode()
	{
		func_t* fnc = di->decompiledFunction;
		auto fit = di->fnc2code.find(fnc);
		if (fit == di->fnc2code.end())
		{
			return;
		}
		qstring fncCmt;
		if (get_func_cmt(&fncCmt, fnc, false) <= 0)
		{
			return;
		}

		auto& code = fit->second.code;
		std::istringstream f(code);
		std::string line;
		std::list<std::string> lines;
		while (std::getline(f, line))
		{
			lines.push_back(line.c_str());
		}
		bool active = false;
		for (auto it = lines.begin(); it!= lines.end(); ++it)
		{
			std::string l = *it;

			std::regex e1(std::string(SCOLOR_ON)
					+ SCOLOR_AUTOCMT
					+ "// -* Functions -*"
					+ SCOLOR_OFF
					+ SCOLOR_AUTOCMT);

			if (std::regex_match(l, e1))
			{
				active = true;
				continue;
			}

			if (!active)
			{
				continue;
			}

			std::regex e2(std::string(SCOLOR_ON)
					+ SCOLOR_AUTOCMT
					+ "// Comment:.*"
					+ SCOLOR_OFF
					+ SCOLOR_AUTOCMT);

			if (std::regex_match(l, e2))
			{
				std::regex e3(std::string(SCOLOR_ON)
						+ SCOLOR_AUTOCMT
						+ "// .*"
						+ SCOLOR_OFF
						+ SCOLOR_AUTOCMT);

				while (std::regex_match(l, e3))
				{
					it = lines.erase(it);
					if (it == lines.end())
						break;
					l = *it;
				}
			}
			if (it == lines.end())
				break;

			qstring cFncName;
			get_func_name(&cFncName, fnc->start_ea);
			std::string tmpFncName = cFncName.c_str();
			std::string tmpFncNameTrim = tmpFncName;
			tmpFncNameTrim.erase(0, tmpFncNameTrim.find_first_not_of('_'));

			std::regex e4(".*"
					+ std::string(SCOLOR_ON)
					+ SCOLOR_DEFAULT
					+ tmpFncName
					+ SCOLOR_OFF
					+ SCOLOR_DEFAULT
					+ ".*" );

			std::regex e5(".*"
					+ std::string(SCOLOR_ON)
					+ SCOLOR_DEFAULT
					+ tmpFncNameTrim
					+ SCOLOR_OFF
					+ SCOLOR_DEFAULT
					+ ".*" );

			if (std::regex_match(l, e4) || std::regex_match(l, e5))
			{
				bool first = true;
				std::istringstream ff(fncCmt.c_str());
				std::string cLine;
				while (std::getline(ff, cLine))
				{
					if (first)
					{
						std::string prolog = std::string(SCOLOR_ON)
								+ SCOLOR_AUTOCMT
								+ "// Comment:"
								+ SCOLOR_OFF
								+ SCOLOR_AUTOCMT;

						lines.insert(it, prolog);
						first = false;
					}

					cLine = std::string(SCOLOR_ON)
							+ SCOLOR_AUTOCMT
							+ "//     "
							+ cLine
							+ SCOLOR_OFF
							+ SCOLOR_AUTOCMT;

					lines.insert(it, cLine);
				}

				break;
			}
		}

		fit->second.code.clear();
		for (auto& l : lines)
			fit->second.code += l + "\n";
	}
};

} // namespace idaplugin

#endif
