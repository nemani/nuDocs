define([
    'jquery',
    '/common/modes.js',
    '/common/themes.js',
    '/customize/messages.js',
    '/common/common-ui-elements.js',
    '/common/inner/common-mediatag.js',
    '/common/common-hash.js',
    '/common/common-util.js',
    '/common/text-cursor.js',
    '/bower_components/chainpad/chainpad.dist.js',
], function ($, Modes, Themes, Messages, UIElements, MT, Hash, Util, TextCursor, ChainPad) {
    var module = {};

     var cursorToPos = module.cursorToPos = function(cursor, oldText) {
        var cLine = cursor.line;
        var cCh = cursor.ch;
        var pos = 0;
        var textLines = oldText.split("\n");
        for (var line = 0; line <= cLine; line++) {
            if(line < cLine) {
                pos += textLines[line].length+1;
            }
            else if(line === cLine) {
                pos += cCh;
            }
        }
        return pos;
    };

    var posToCursor = module.posToCursor = function(position, newText) {
        var cursor = {
            line: 0,
            ch: 0
        };
        var textLines = newText.substr(0, position).split("\n");
        cursor.line = textLines.length - 1;
        cursor.ch = textLines[cursor.line].length;
        return cursor;
    };

    module.getContentExtension = function (mode) {
        var ext = Modes.extensionOf(mode);
        return ext !== undefined ? ext : '.txt';
    };
    module.fileExporter = function (content) {
        return new Blob([ content ], { type: 'text/plain;charset=utf-8' });
    };
    module.setValueAndCursor = function (editor, oldDoc, remoteDoc) {
        editor._noCursorUpdate = true;
        var scroll = editor.getScrollInfo();
        //get old cursor here
        var oldCursor = {};
        oldCursor.selectionStart = cursorToPos(editor.getCursor('from'), oldDoc);
        oldCursor.selectionEnd = cursorToPos(editor.getCursor('to'), oldDoc);

        editor.setValue(remoteDoc);
        editor.save();

        var ops = ChainPad.Diff.diff(oldDoc, remoteDoc);
        var selects = ['selectionStart', 'selectionEnd'].map(function (attr) {
            return TextCursor.transformCursor(oldCursor[attr], ops);
        });

        editor._noCursorUpdate = false;
        editor.scrollTo(scroll.left, scroll.top);

        if (!editor.hasFocus()) { return; }

        if(selects[0] === selects[1]) {
            editor.setCursor(posToCursor(selects[0], remoteDoc));
        }
        else {
            editor.setSelection(posToCursor(selects[0], remoteDoc), posToCursor(selects[1], remoteDoc));
        }
    };

    module.handleImagePaste = function (editor) {
        // Don't paste file path in the users wants to paste a file
        editor.on('paste', function (editor, ev) {
            try {
                if (!ev.clipboardData.items) { return; }
                var items = Array.prototype.slice.apply(ev.clipboardData.items);
                var hasFile = items.some(function (el) {
                    return el.kind === "file";
                });
                if (!hasFile) { return; }
                ev.preventDefault();
            } catch (e) { console.error(e); }
        });
    };

    module.getHeadingText = function (editor) {
        var lines = editor.getValue().split(/\n/);

        var text = '';
        lines.some(function (line) {
            // lines including a c-style comment are also valuable
            var clike = /^\s*(\/\*|\/\/)(.*)?(\*\/)*$/;
            if (clike.test(line)) {
                line.replace(clike, function (a, one, two) {
                    if (!(two && two.replace)) { return; }
                    text = two.replace(/\*\/\s*$/, '').trim();
                });
                return true;
            }

            // lisps?
            var lispy = /^\s*(;|#\|)+(.*?)$/;
            if (lispy.test(line)) {
                line.replace(lispy, function (a, one, two) {
                    text = two;
                });
                return true;
            }

            // lines beginning with a hash are potentially valuable
            // works for markdown, python, bash, etc.
            var hash = /^#+(.*?)$/;
            var hashAndLink = /^#+\s*\[(.*?)\]\(.*\)\s*$/;
            if (hash.test(line)) {
                // test for link inside the title, and set text just to the name of the link
                if (hashAndLink.test(line)) {
                    line.replace(hashAndLink, function (a, one) {
                        text = Util.stripTags(one);
                    });
                    return true;
                }
                line.replace(hash, function (a, one) {
                    text = Util.stripTags(one);
                });
                return true;
            }

            // TODO make one more pass for multiline comments
        });

        return text.trim();
    };

    module.mkIndentSettings = function (editor, metadataMgr) {
        var setIndentation = function (units, useTabs, fontSize, spellcheck, brackets) {
            if (typeof(units) !== 'number') { return; }
            var doc = editor.getDoc();
            editor.setOption('indentUnit', units);
            editor.setOption('tabSize', units);
            editor.setOption('indentWithTabs', useTabs);
            editor.setOption('spellcheck', spellcheck);
            editor.setOption('autoCloseBrackets', brackets);
            setTimeout(function () {
                $('.CodeMirror').css('font-size', fontSize+'px');
                editor.refresh();
            });

            // orgmode is using its own shortcuts
            if (editor.getMode().name === 'orgmode') { return; }
            editor.setOption("extraKeys", {
                Tab: function() {
                    if (doc.somethingSelected()) {
                        editor.execCommand("indentMore");
                    }
                    else {
                        if (!useTabs) { editor.execCommand("insertSoftTab"); }
                        else { editor.execCommand("insertTab"); }
                    }
                },
                "Shift-Tab": function () {
                    editor.execCommand("indentLess");
                },
                "Alt-Left": undefined,
                "Alt-Right": undefined,
                "Alt-Enter": undefined, 
                "Alt-Up": undefined,
                "Alt-Down": undefined,
                "Shift-Alt-Left": undefined,
                "Shift-Alt-Right": undefined,
                "Shift-Alt-Enter": undefined,
                "Shift-Alt-Up": undefined,
                "Shift-Alt-Down": undefined,
            });
        };

        var indentKey = 'indentUnit';
        var useTabsKey = 'indentWithTabs';
        var fontKey = 'fontSize';
        var spellcheckKey = 'spellcheck';
        var updateIndentSettings = editor.updateSettings = function () {
            if (!metadataMgr) { return; }
            var data = metadataMgr.getPrivateData().settings;
            data = data.codemirror || {};
            var indentUnit = data[indentKey];
            var useTabs = data[useTabsKey];
            var fontSize = data[fontKey];
            var spellcheck = data[spellcheckKey];
            var brackets = data.brackets;
            setIndentation(
                typeof(indentUnit) === 'number'? indentUnit : 2,
                typeof(useTabs) === 'boolean'? useTabs : false,
                typeof(fontSize) === 'number' ? fontSize : 12,
                typeof(spellcheck) === 'boolean' ? spellcheck : false,
                typeof(brackets) === 'boolean' ? brackets : true);
        };
        metadataMgr.onChangeLazy(updateIndentSettings);
        updateIndentSettings();
    };

    module.create = function (defaultMode, CMeditor, textarea) {
        var exp = {};

        var CodeMirror = exp.CodeMirror = CMeditor;
        CodeMirror.modeURL = "cm/mode/%N/%N";

        var $pad = $('#pad-iframe');
        var $textarea = exp.$textarea = textarea ? $(textarea) : $('#editor1');
        if (!$textarea.length) { $textarea = exp.$textarea = $pad.contents().find('#editor1'); }

        var Title;
        var onLocal = function () {};
        var $drawer;
        exp.init = function (local, title, toolbar) {
            if (typeof local === "function") {
                onLocal = local;
            }
            Title = title;
            $drawer = toolbar.$theme || $();
        };

        var editor = exp.editor = CMeditor.fromTextArea($textarea[0], {
            allowDropFileTypes: [],
            lineNumbers: true,
            lineWrapping: true,
            autoCloseBrackets: true,
            matchBrackets : true,
            showTrailingSpace : true,
            styleActiveLine : true,
            search: true,
            inputStyle: 'contenteditable',
            highlightSelectionMatches: {showToken: /\w+/},
            extraKeys: {"Shift-Ctrl-R": undefined},
            foldGutter: true,
            gutters: ["CodeMirror-linenumbers", "CodeMirror-foldgutter"],
            mode: defaultMode || "javascript",
            readOnly: true
        });
        editor.focus();

        // Fix cursor and scroll position after undo/redo
        var undoData;
        editor.on('beforeChange', function (editor, change) {
            if (change.origin !== "undo" && change.origin !== "redo") { return; }
            undoData = editor.getValue();
        });
        editor.on('change', function (editor, change) {
            if (change.origin !== "undo" && change.origin !== "redo") { return; }
            if (typeof(undoData) === "undefined") { return; }
            var doc = editor.getValue();
            var ops = ChainPad.Diff.diff(undoData, doc);
            undoData = undefined;
            if (!ops.length) { return; }
            var cursor = posToCursor(ops[0].offset, doc);
            editor.setCursor(cursor);
            editor.scrollIntoView(cursor);
        });

        module.handleImagePaste(editor);

        var setMode = exp.setMode = function (mode, cb) {
            exp.highlightMode = mode;
            if (mode === 'markdown') { mode = 'gfm'; }
            if (/text\/x/.test(mode)) {
                CMeditor.autoLoadMode(editor, 'clike');
                editor.setOption('mode', mode);
            } else {
                if (mode !== "text") {
                    CMeditor.autoLoadMode(editor, mode);
                }
                editor.setOption('mode', mode);
            }
            if (exp.$language) {
                var name = exp.$language.find('a[data-value="' + mode + '"]').text() || undefined;
                name = name ? Messages.languageButton + ' ('+name+')' : Messages.languageButton;
                exp.$language.setValue(mode, name);
            }

                if (mode === "orgmode") {
                    if (CodeMirror.orgmode && typeof (CodeMirror.orgmode.init) === "function") {
                        CodeMirror.orgmode.init(editor);
                    }
                } else {
                    if (CodeMirror.orgmode && typeof (CodeMirror.orgmode.destroy) === "function") {
                        CodeMirror.orgmode.destroy(editor);
                    }
                }

            if(cb) { cb(mode); }
        };

        var setTheme = exp.setTheme = (function () {
            var path = '/common/theme/';

            var $head = $(window.document.head);

            var themeLoaded = exp.themeLoaded = function (theme) {
                return $head.find('link[href*="'+theme+'"]').length;
            };

            var loadTheme = exp.loadTheme = function (theme) {
                $head.append($('<link />', {
                    rel: 'stylesheet',
                    href: path + theme + '.css',
                }));
            };

            return function (theme, $select) {
                if (!theme) {
                    editor.setOption('theme', 'default');
                } else {
                    if (!themeLoaded(theme)) {
                        loadTheme(theme);
                    }
                    editor.setOption('theme', theme);
                }
                if ($select) {
                    var name = theme || undefined;
                    name = name ? Messages.themeButton + ' ('+theme+')' : Messages.themeButton;
                    $select.setValue(theme, name);
                }
            };
        }());

        exp.getHeadingText = function () {
            return module.getHeadingText(editor);
        };

        exp.configureLanguage = function (Common, cb, onModeChanged) {
            var options = [];
            Modes.list.forEach(function (l) {
                options.push({
                    tag: 'a',
                    attributes: {
                        'data-value': l.mode,
                        'href': '#',
                    },
                    content: l.language // Pretty name of the language value
                });
            });
            var dropdownConfig = {
                text: Messages.languageButton, // Button initial text
                options: options, // Entries displayed in the menu
                isSelect: true,
                feedback: 'CODE_LANGUAGE',
                common: Common
            };
            var $block = exp.$language = UIElements.createDropdown(dropdownConfig);
            $block.find('button').attr('title', Messages.languageButtonTitle);

            var isHovering = false;
            var $aLanguages = $block.find('a');
            $aLanguages.mouseenter(function () {
                isHovering = true;
                setMode($(this).attr('data-value'));
            });
            $aLanguages.mouseleave(function () {
                if (isHovering) {
                    setMode($block.find(".cp-dropdown-element-active").attr('data-value'));
                }
            });
            $aLanguages.click(function () {
                isHovering = false;
                var mode = $(this).attr('data-value');
                setMode(mode, onModeChanged);
                onLocal();
            });

            if ($drawer) { $drawer.append($block); }
            if (exp.highlightMode) { exp.setMode(exp.highlightMode); }
            if (cb) { cb(); }
        };

        exp.configureTheme = function (Common, cb) {
            /*  Remember the user's last choice of theme using localStorage */
            var themeKey = ['codemirror', 'theme'];

            var todo = function (err, lastTheme) {
                lastTheme = lastTheme || 'default';
                var options = [];
                Themes.forEach(function (l) {
                    options.push({
                        tag: 'a',
                        attributes: {
                            'data-value': l.name,
                            'href': '#',
                        },
                        content: l.name // Pretty name of the language value
                    });
                });
                var dropdownConfig = {
                    text: Messages.code_editorTheme, // Button initial text
                    options: options, // Entries displayed in the menu
                    isSelect: true,
                    initialValue: lastTheme,
                    feedback: 'CODE_THEME',
                    common: Common
                };
                var $block = exp.$theme = UIElements.createDropdown(dropdownConfig);
                $block.find('button').attr('title', Messages.themeButtonTitle).click(function () {
                    var state = $block.find('.cp-dropdown-content').is(':visible');
                    var $c = $block.closest('.cp-toolbar-drawer-content');
                    $c.removeClass('cp-dropdown-visible');
                    if (!state) {
                        $c.addClass('cp-dropdown-visible');
                    }
                });

                setTheme(lastTheme, $block);

                var isHovering = false;
                var $aThemes = $block.find('a');
                $aThemes.mouseenter(function () {
                    isHovering = true;
                    var theme = $(this).attr('data-value');
                    setTheme(theme, $block);
                });
                $aThemes.mouseleave(function () {
                    if (isHovering) {
                        setTheme(lastTheme, $block);
                        Common.setAttribute(themeKey, lastTheme);
                    }
                });
                $aThemes.click(function () {
                    isHovering = false;
                    var theme = $(this).attr('data-value');
                    setTheme(theme, $block);
                    Common.setAttribute(themeKey, theme);
                });

                if ($drawer) { $drawer.append($block); }
                if (cb) { cb(); }
            };
            Common.getAttribute(themeKey, todo);
        };

        exp.getContentExtension = function () {
            return module.getContentExtension(exp.highlightMode);
        };
        exp.fileExporter = function () {
            return module.fileExporter(editor.getValue());
        };
        exp.fileImporter = function (content, file) {
            var $toolbarContainer = $('#cme_toolbox');
            var mime = CodeMirror.findModeByMIME(file.type);
            var mode;
            if (!mime) {
                var ext = /.+\.([^.]+)$/.exec(file.name);
                if (ext && ext[1]) {
                    mode = CMeditor.findModeByExtension(ext[1]);
                    mode = mode && mode.mode || null;
                }
            } else {
                mode = mime && mime.mode || null;
            }
            if (mode === "markdown") { mode = "gfm"; }
            if (mode && Modes.list.some(function (o) { return o.mode === mode; })) {
                exp.setMode(mode);
                $toolbarContainer.find('#language-mode').val(mode);
            } else {
                console.log("Couldn't find a suitable highlighting mode: %s", mode);
                exp.setMode('text');
                $toolbarContainer.find('#language-mode').val('text');
            }
            // return the mode so that the code editor can decide how to display the new content
            return { content: content, mode: mode };
        };

        exp.setValueAndCursor = function (oldDoc, remoteDoc) {
            return module.setValueAndCursor(editor, oldDoc, remoteDoc);
        };

        /////

        var canonicalize = exp.canonicalize = function (t) { return t.replace(/\r\n/g, '\n'); };


        exp.contentUpdate = function (newContent) {
            var oldDoc = canonicalize(editor.getValue());
            var remoteDoc = newContent.content;
            // setValueAndCursor triggers onLocal, even if we don't make any change to the content
            // and it may revert other changes (metadata)

            if (oldDoc === remoteDoc) { return; }
            exp.setValueAndCursor(oldDoc, remoteDoc);
        };

        exp.getContent = function () {
            editor.save();
            return { content: canonicalize(editor.getValue()) };
        };

        exp.mkIndentSettings = function (metadataMgr) {
            module.mkIndentSettings(editor, metadataMgr);
        };

        exp.getCursor = function () {
            var doc = canonicalize(editor.getValue());
            var cursor = {};
            cursor.selectionStart = cursorToPos(editor.getCursor('from'), doc);
            cursor.selectionEnd = cursorToPos(editor.getCursor('to'), doc);
            return cursor;
        };

        var makeCursor = function (id) {
            if (document.getElementById(id)) {
                return document.getElementById(id);
            }
            return $('<span>', {
                'id': id,
                'class': 'cp-codemirror-cursor'
            })[0];
        };
        var makeTippy = function (cursor) {
            return MT.getCursorAvatar(cursor);
        };
        var marks = {};
        exp.removeCursors = function () {
            for (var id in marks) {
                marks[id].clear();
                delete marks[id];
            }
        };
        exp.setRemoteCursor = function (data) {
            if (data.leave) {
                $('.cp-codemirror-cursor[id^='+data.id+']').each(function (i, el) {
                    var id = $(el).attr('id');
                    if (marks[id]) {
                        marks[id].clear();
                        delete marks[id];
                    }
                });
                return;
            }

            var id = data.id;
            var cursor = data.cursor;
            var doc = canonicalize(editor.getValue());

            if (marks[id]) {
                marks[id].clear();
                delete marks[id];
            }

            if (!cursor.selectionStart) { return; }

            if (cursor.selectionStart === cursor.selectionEnd) {
                var cursorPosS = posToCursor(cursor.selectionStart, doc);
                var el = makeCursor(id);
                if (cursor.color) {
                    $(el).css('border-color', cursor.color)
                         .css('background-color', cursor.color);
                }
                if (cursor.name) {
                    $(el).attr('title', makeTippy(cursor))
                         .attr('data-cptippy-html', true);
                }
                marks[id] = editor.setBookmark(cursorPosS, { widget: el });
            } else {
                var pos1 = posToCursor(cursor.selectionStart, doc);
                var pos2 = posToCursor(cursor.selectionEnd, doc);
                var css = cursor.color
                    ? 'background-color: rgba(' + Util.hexToRGB(cursor.color).join(',') + ',0.2)'
                    : 'background-color: rgba(255,0,0,0.2)';
                marks[id] = editor.markText(pos1, pos2, {
                    css: css,
                    attributes: {
                        'data-cptippy-html': true,
                    },
                    title: makeTippy(cursor),
                    className: 'cp-tippy-html'
                });
            }
        };

        return exp;
    };

    return module;
});

