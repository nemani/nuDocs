require(['/api/config'], function(ApiConfig) {
    // see ckeditor_base.js getUrl()
    window.CKEDITOR_GETURL = function(resource) {
        if (resource.indexOf('/') === 0) {
            resource = window.CKEDITOR.basePath.replace(/\/bower_components\/.*/, '') + resource;
        } else if (resource.indexOf(':/') === -1) {
            resource = window.CKEDITOR.basePath + resource;
        }
        if (resource[resource.length - 1] !== '/' && resource.indexOf('ver=') === -1) {
            var args = ApiConfig.requireConf.urlArgs;
            resource += (resource.indexOf('?') >= 0 ? '&' : '?') + args;
        }
        return resource;
    };

    window.MathJax = {
        "HTML-CSS": {
        },
        TeX: {
        }
    };

    require(['/bower_components/ckeditor/ckeditor.js']);
});
define([
    'jquery',
    '/bower_components/hyperjson/hyperjson.js',
    '/common/sframe-app-framework.js',
    '/common/cursor.js',
    '/common/TypingTests.js',
    '/customize/messages.js',
    '/pad/links.js',
    '/pad/comments.js',
    '/pad/export.js',
    '/pad/cursor.js',
    '/bower_components/nthen/index.js',
    '/common/media-tag.js',
    '/api/config',
    '/common/common-hash.js',
    '/common/common-util.js',
    '/common/common-interface.js',
    '/common/common-ui-elements.js',
    '/common/hyperscript.js',
    '/bower_components/chainpad/chainpad.dist.js',
    '/customize/application_config.js',
    '/common/test.js',

    '/bower_components/diff-dom/diffDOM.js',

    'css!/customize/src/print.css',
    'css!/bower_components/bootstrap/dist/css/bootstrap.min.css',
    'css!/bower_components/components-font-awesome/css/font-awesome.min.css',
    'less!/pad/app-pad.less'
], function(
    $,
    Hyperjson,
    Framework,
    Cursor,
    TypingTest,
    Messages,
    Links,
    Comments,
    Exporter,
    Cursors,
    nThen,
    MediaTag,
    ApiConfig,
    Hash,
    Util,
    UI,
    UIElements,
    h,
    ChainPad,
    AppConfig,
    Test
) {
    var DiffDom = window.diffDOM;

    var slice = function(coll) {
        return Array.prototype.slice.call(coll);
    };

    var removeListeners = function(root) {
        slice(root.attributes).map(function(attr) {
            if (/^on/.test(attr.name)) {
                root.attributes.removeNamedItem(attr.name);
            }
        });
        slice(root.children).forEach(removeListeners);
    };

    var hjsonToDom = function(H) {
        var dom = Hyperjson.toDOM(H);
        removeListeners(dom);
        return dom;
    };

    var module = window.REALTIME_MODULE = window.APP = {
        Hyperjson: Hyperjson,
        logFights: true,
        fights: [],
        Cursor: Cursor,
    };

    // MEDIATAG: Filter elements to serialize
    // * Remove the drag&drop and resizers from the hyperjson
    var isWidget = function(el) {
        return typeof(el.getAttribute) === "function" &&
            (el.getAttribute('data-cke-hidden-sel') ||
                (el.getAttribute('class') &&
                    (/cke_widget_drag/.test(el.getAttribute('class')) ||
                        /cke_image_resizer/.test(el.getAttribute('class')))
                )
            );
    };

    var isNotMagicLine = function(el) {
        return !(el && typeof(el.getAttribute) === 'function' &&
            el.getAttribute('class') &&
            el.getAttribute('class').split(' ').indexOf('non-realtime') !== -1);
    };

    var isCursor = Cursors.isCursor;

    var shouldSerialize = function(el) {
        return isNotMagicLine(el) && !isWidget(el) && !isCursor(el);
    };

    // MEDIATAG: Filter attributes in the serialized elements
    var widgetFilter = function(hj) {
        // Send a widget ID == 0 to avoid a fight between browsers and
        // prevent the container from having the "selected" class (blue border)
        if (hj[1].class) {
            var split = hj[1].class.split(' ');
            if (split.indexOf('cke_widget_wrapper') !== -1 &&
                split.indexOf('cke_widget_block') !== -1) {
                hj[1].class = "cke_widget_wrapper cke_widget_block";
                hj[1]['data-cke-widget-id'] = "0";
            }
            if (split.indexOf('cke_widget_wrapper') !== -1 &&
                split.indexOf('cke_widget_inline') !== -1) {
                hj[1].class = "cke_widget_wrapper cke_widget_inline";
                delete hj[1]['data-cke-widget-id'];
                //hj[1]['data-cke-widget-id'] = "0";
            }
            // Remove the title attribute of the drag&drop icons (translation conflicts)
            if (split.indexOf('cke_widget_drag_handler') !== -1 ||
                split.indexOf('cke_image_resizer') !== -1) {
                hj[1].title = undefined;
            }
        }
        return hj;
    };

    var hjsonFilters = function(hj) {
        /* catch `type="_moz"` before it goes over the wire */
        var brFilter = function(hj) {
            if (hj[1].type === '_moz') { hj[1].type = undefined; }
            return hj;
        };
        var mediatagContentFilter = function(hj) {
            if (hj[0] === 'MEDIA-TAG') { hj[2] = []; }
            return hj;
        };
        var commentActiveFilter = function(hj) {
            if (hj[0] === 'COMMENT') { delete(hj[1] || {}).class; }
            return hj;
        };
        brFilter(hj);
        mediatagContentFilter(hj);
        commentActiveFilter(hj);
        widgetFilter(hj);
        return hj;
    };

    var domFromHTML = function(html) {
        return new DOMParser().parseFromString(html, 'text/html');
    };

    var forbiddenTags = [
        'SCRIPT',
        //'IFRAME',
        'OBJECT',
        'APPLET',
        //'VIDEO',
        //'AUDIO'
    ];

    var CKEDITOR_CHECK_INTERVAL = 100;
    var ckEditorAvailable = function(cb) {
        var intr;
        var check = function() {
            if (window.CKEDITOR) {
                clearTimeout(intr);
                cb(window.CKEDITOR);
            }
        };
        intr = setInterval(function() {
            console.log("Ckeditor was not defined. Trying again in %sms", CKEDITOR_CHECK_INTERVAL);
            check();
        }, CKEDITOR_CHECK_INTERVAL);
        check();
    };

    var mkHelpMenu = function(framework) {
        var $toolbarContainer = $('.cke_toolbox_main');
        var helpMenu = framework._.sfCommon.createHelpMenu(['text', 'pad']);
        $toolbarContainer.before(helpMenu.menu);

        framework._.toolbar.$drawer.append(helpMenu.button);
    };

    var mkDiffOptions = function(cursor, readOnly) {
        return {
            preDiffApply: function(info) {
                /*
                    Don't accept attributes that begin with 'on'
                    these are probably listeners, and we don't want to
                    send scripts over the wire.
                */
                if (['addAttribute', 'modifyAttribute'].indexOf(info.diff.action) !== -1) {
                    if (info.diff.name === 'href') {
                        // console.log(info.diff);
                        //var href = info.diff.newValue;

                        // TODO normalize HTML entities
                        if (/javascript *: */.test(info.diff.newValue)) {
                            // TODO remove javascript: links
                        }
                    }

                    if (/^on/.test(info.diff.name)) {
                        console.log("Rejecting forbidden element attribute with name (%s)", info.diff.name);
                        return true;
                    }
                }

                // Other users cursor
                if (Cursors.preDiffApply(info)) {
                    return true;
                }

                if (info.node && info.node.tagName === 'DIV' &&
                    info.node.getAttribute('class') &&
                    /cp-link-clicked/.test(info.node.getAttribute('class'))) {
                    if (info.diff.action === 'removeElement') {
                        return true;
                    }
                }

                // MEDIATAG
                // Never modify widget ids
                if (info.node && info.node.tagName === 'SPAN' && info.diff.name === 'data-cke-widget-id') {
                    return true;
                }
                if (info.node && info.node.tagName === 'SPAN' &&
                    info.node.getAttribute('class') &&
                    /cke_widget_wrapper/.test(info.node.getAttribute('class'))) {
                    if (info.diff.action === 'modifyAttribute' && info.diff.name === 'class') {
                        return true;
                    }
                    //console.log(info);
                }
                // CkEditor drag&drop icon container
                if (info.node && info.node.tagName === 'SPAN' &&
                    info.node.getAttribute('class') &&
                    info.node.getAttribute('class').split(' ').indexOf('cke_widget_drag_handler_container') !== -1) {
                    return true;
                }
                // CkEditor drag&drop title (language fight)
                if (info.node && info.node.getAttribute &&
                    info.node.getAttribute('class') &&
                    (info.node.getAttribute('class').split(' ').indexOf('cke_widget_drag_handler') !== -1 ||
                        info.node.getAttribute('class').split(' ').indexOf('cke_image_resizer') !== -1)) {
                    return true;
                }


                /*
                    Also reject any elements which would insert any one of
                    our forbidden tag types: script, iframe, object,
                        applet, video, or audio
                */
                if (['addElement', 'replaceElement'].indexOf(info.diff.action) !== -1) {
                    if (info.diff.element && forbiddenTags.indexOf(info.diff.element.nodeName) !== -1) {
                        console.log("Rejecting forbidden tag of type (%s)", info.diff.element.nodeName);
                        return true;
                    } else if (info.diff.newValue && forbiddenTags.indexOf(info.diff.newValue.nodeType) !== -1) {
                        console.log("Rejecting forbidden tag of type (%s)", info.diff.newValue.nodeName);
                        return true;
                    }
                }

                // Don't remote the "active" class of our comments
                if (info.node && info.node.tagName === 'COMMENT') {
                    if (info.diff.action === 'removeAttribute' && ['class'].indexOf(info.diff.name) !== -1) {
                        return true;
                    }
                }

                if (info.node && info.node.tagName === 'BODY') {
                    if (info.diff.action === 'removeAttribute' && ['class', 'spellcheck'].indexOf(info.diff.name) !== -1) {
                        return true;
                    }
                }

                /* DiffDOM will filter out magicline plugin elements
                    in practice this will make it impossible to use it
                    while someone else is typing, which could be annoying.

                    we should check when such an element is going to be
                    removed, and prevent that from happening. */
                if (info.node && info.node.tagName === 'SPAN' &&
                    info.node.getAttribute('contentEditable') === "false") {
                    // it seems to be a magicline plugin element...
                    // but it can also be a widget (MEDIATAG), in which case the removal was
                    // probably intentional

                    if (info.diff.action === 'removeElement') {
                        // and you're about to remove it...
                        if (!info.node.getAttribute('class') ||
                            !/cke_widget_wrapper/.test(info.node.getAttribute('class'))) {
                            // This element is not a widget!
                            // this probably isn't what you want
                            /*
                                I have never seen this in the console, but the
                                magic line is still getting removed on remote
                                edits. This suggests that it's getting removed
                                by something other than diffDom.
                            */
                            console.log("preventing removal of the magic line!");

                            // return true to prevent diff application
                            return true;
                        }
                    }
                }

                // Do not change the spellcheck value in view mode
                if (readOnly && info.node && info.node.tagName === 'BODY' &&
                    info.diff.action === 'modifyAttribute' && info.diff.name === 'spellcheck') {
                    return true;
                }
                // Do not change the contenteditable value in view mode
                if (readOnly && info.node && info.node.tagName === 'BODY' &&
                    info.diff.action === 'modifyAttribute' && info.diff.name === 'contenteditable') {
                    return true;
                }

                /*
                                cursor.update();

                                // no use trying to recover the cursor if it doesn't exist
                                if (!cursor.exists()) { return; }

                                /*  frame is either 0, 1, 2, or 3, depending on which
                                    cursor frames were affected: none, first, last, or both
                                */
                /*
                                var frame = info.frame = cursor.inNode(info.node);

                                if (!frame) { return; }

                                if (frame && typeof info.diff.oldValue === 'string' && typeof info.diff.newValue === 'string') {
                                    //var pushes = cursor.pushDelta(info.diff.oldValue, info.diff.newValue);
                                    var ops = ChainPad.Diff.diff(info.diff.oldValue, info.diff.newValue);

                                    if (frame & 1) {
                                        // push cursor start if necessary
                                        cursor.transformRange(cursor.Range.start, ops);
                                    }
                                    if (frame & 2) {
                                        // push cursor end if necessary
                                        cursor.transformRange(cursor.Range.end, ops);
                                    }
                                }
                */
            },
            /*
                        postDiffApply: function (info) {
                            if (info.frame) {
                                if (info.node) {
                                    if (info.frame & 1) { cursor.fixStart(info.node); }
                                    if (info.frame & 2) { cursor.fixEnd(info.node); }
                                } else { console.error("info.node did not exist"); }

                                var sel = cursor.makeSelection();
                                var range = cursor.makeRange();

                                cursor.fixSelection(sel, range);
                            }
                        }
            */
        };
    };

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////

    var addToolbarHideBtn = function(framework, $bar) {
        // Expand / collapse the toolbar
        var cfg = {
            element: $bar
        };
        var onClick = function(visible) {
            framework._.sfCommon.setAttribute(['pad', 'showToolbar'], visible);
        };
        framework._.sfCommon.getAttribute(['pad', 'showToolbar'], function(err, data) {
            var state = false;
            if (($(window).height() >= 800 || $(window).width() >= 800) &&
                (typeof(data) === "undefined" || data)) {
                state = true;
                $('.cke_toolbox_main').show();
            } else {
                $('.cke_toolbox_main').hide();
            }
            var $collapse = framework._.sfCommon.createButton('toggle', true, cfg, onClick);
            framework._.toolbar.$bottomL.append($collapse);
            if (state) {
                $collapse.addClass('cp-toolbar-button-active');
            }
        });
    };

    var addTOCHideBtn = function(framework, $toc) {
        // Expand / collapse the toolbar
        var onClick = function(visible) {
            framework._.sfCommon.setAttribute(['pad', 'showTOC'], visible);
        };
        framework._.sfCommon.getAttribute(['pad', 'showTOC'], function(err, data) {
            var state = false;
            if (($(window).height() >= 800 || $(window).width() >= 800) &&
                (typeof(data) === "undefined" || data)) {
                state = true;
                $toc.show();
            } else {
                $toc.hide();
            }
            var $tocButton = framework._.sfCommon.createButton('', true, {
                drawer: false,
                text: Messages.pad_tocHide,
                name: 'pad_toc',
                icon: 'fa-list-ul',
            }, function () {
                $tocButton.removeClass('cp-toolbar-button-active');
                $toc.toggle();
                state = $toc.is(':visible');
                if (state) {
                    $tocButton.addClass('cp-toolbar-button-active');
                }
                onClick(state);
            });
            framework._.toolbar.$bottomL.append($tocButton);
            if (state) {
                $tocButton.addClass('cp-toolbar-button-active');
            }
        });
    };

    var displayMediaTags = function(framework, dom, mediaTagMap) {
        setTimeout(function() { // Just in case
            var tags = dom.querySelectorAll('media-tag:empty');
            Array.prototype.slice.call(tags).forEach(function(el) {
                MediaTag(el);
                $(el).on('keydown', function(e) {
                    if ([8, 46].indexOf(e.which) !== -1) {
                        $(el).remove();
                        framework.localChange();
                    }
                });
                var observer = new MutationObserver(function(mutations) {
                    mutations.forEach(function(mutation) {
                        if (mutation.type === 'childList') {
                            var list_values = [].slice.call(el.children);
                            mediaTagMap[el.getAttribute('src')] = list_values;
                        }
                    });
                });
                observer.observe(el, {
                    attributes: false,
                    childList: true,
                    characterData: false
                });
            });
        });
    };

    var restoreMediaTags = function(tempDom, mediaTagMap) {
        var tags = tempDom.querySelectorAll('media-tag:empty');
        Array.prototype.slice.call(tags).forEach(function(tag) {
            var src = tag.getAttribute('src');
            if (mediaTagMap[src]) {
                mediaTagMap[src].forEach(function(n) {
                    tag.appendChild(n.cloneNode());
                });
            }
        });
    };

    var mkPrintButton = function (framework, editor) {
        var $printButton = framework._.sfCommon.createButton('print', true);
        $printButton.click(function () {
            /*
            // NOTE: alternative print system in case we keep having more issues on Firefox
            var $iframe = $('html').find('iframe');
            var iframe = $iframe[0].contentWindow;
            iframe.print();
            */
            editor.execCommand('print');
            framework.feedback('PRINT_PAD');
        });
        framework._.toolbar.$drawer.append($printButton);
    };

    var andThen2 = function(editor, Ckeditor, framework) {
        var mediaTagMap = {};
        var $contentContainer = $('#cke_1_contents');
        var $html = $('html');
        var $faLink = $html.find('head link[href*="/bower_components/components-font-awesome/css/font-awesome.min.css"]');
        if ($faLink.length) {
            $html.find('iframe').contents().find('head').append($faLink.clone());
        }

        var ml = editor._.magiclineBackdoor.that.line.$;
        [ml, ml.parentElement].forEach(function(el) {
            el.setAttribute('class', 'non-realtime');
        });

        window.editor = editor;

        var $iframe = $('html').find('iframe').contents();
        var ifrWindow = $html.find('iframe')[0].contentWindow;

        var customCss = '/customize/ckeditor-contents.css?' + window.CKEDITOR.CRYPTPAD_URLARGS;
        $iframe.find('head').append('<link href="' + customCss + '" type="text/css" rel="stylesheet" _fcktemp="true"/>');

        framework._.sfCommon.addShortcuts(ifrWindow);

        mkPrintButton(framework, editor, Ckeditor);

        var documentBody = ifrWindow.document.body;
        var inner = window.inner = documentBody;
        var $inner = $(inner);

        var observer = new MutationObserver(function(muts) {
            muts.forEach(function(mut) {
                if (mut.type === 'childList') {
                    var $a;
                    for (var i = 0; i < mut.addedNodes.length; i++) {
                        $a = $(mut.addedNodes[i]);
                        if ($a.is('p') && $a.find('> span:empty').length &&
                            $a.find('> br').length && $a.children().length === 2) {
                            $a.find('> span').append($a.find('> br'));
                        }
                    }
                }
            });
        });
        observer.observe(documentBody, {
            childList: true
        });

        var metadataMgr = framework._.sfCommon.getMetadataMgr();
        var privateData = metadataMgr.getPrivateData();
        var common = framework._.sfCommon;

        var comments = Comments.create({
            framework: framework,
            metadataMgr: metadataMgr,
            common: common,
            editor: editor,
            ifrWindow: ifrWindow,
            $iframe: $iframe,
            $inner: $inner,
            $contentContainer: $contentContainer,
            $container: $('#cp-app-pad-comments')
        });

        var $toc = $('#cp-app-pad-toc');
        addTOCHideBtn(framework, $toc);

        // My cursor
        var cursor = module.cursor = Cursor(inner);

        // Display other users cursor
        var cursors = Cursors.create(inner, hjsonToDom, cursor);

        var openLink = function(e) {
            var el = e.currentTarget;
            if (!el || el.nodeName !== 'A') { return; }
            var href = el.getAttribute('href');
            if (href) {
                framework._.sfCommon.openUnsafeURL(href);
            }
        };

        if (!privateData.isEmbed) {
            mkHelpMenu(framework);
        }

        framework._.sfCommon.getAttribute(['pad', 'width'], function(err, data) {
            var active = data || typeof(data) === "undefined";
            if (active) {
                $contentContainer.addClass('cke_body_width');
            } else {
                editor.execCommand('pagemode');
            }
        });

        framework.onEditableChange(function(unlocked) {
            if (!framework.isReadOnly()) {
                $inner.attr('contenteditable', '' + Boolean(unlocked));
            }
            $inner.css({ background: unlocked ? '#fff' : '#eee' });
        });

        framework.setMediaTagEmbedder(function($mt) {
            $mt.attr('contenteditable', 'false');
            //$mt.attr('tabindex', '1');
            //MEDIATAG
            var element = new window.CKEDITOR.dom.element($mt[0]);
            editor.insertElement(element);
            editor.widgets.initOn(element, 'mediatag');
        });

        framework.setTitleRecommender(function() {
            var text;
            if (['h1', 'h2', 'h3'].some(function(t) {
                    var $header = $inner.find(t + ':first-of-type');
                    if ($header.length && $header.text()) {
                        text = $header.text();
                        return true;
                    }
                })) { return text; }
        });

        var DD = new DiffDom(mkDiffOptions(cursor, framework.isReadOnly()));

        var cursorStopped = false;
        var cursorTo;
        var updateCursor = function() {
            if (cursorTo) { clearTimeout(cursorTo); }

            // If we're receiving content
            if (cursorStopped) { return void setTimeout(updateCursor, 100); }

            cursorTo = setTimeout(function() {
                framework.updateCursor();
            }, 500); // 500ms to make sure it is sent after chainpad sync
        };

        var isAnchor = function (el) { return el.nodeName === 'A'; };
        var getAnchorName = function (el) {
            return el.getAttribute('id') ||
                el.getAttribute('data-cke-saved-name') ||
                el.getAttribute('name') ||
                Util.stripTags($(el).text());
        };

        var updateTOC = Util.throttle(function () {
            var toc = [];
            $inner.find('h1, h2, h3, a[id][data-cke-saved-name]').each(function (i, el) {
                if (isAnchor(el)) {
                    return void toc.push({
                        level: 2,
                        el: el,
                        title: getAnchorName(el),
                    });
                }

                toc.push({
                    level: Number(el.tagName.slice(1)),
                    el: el,
                    title: Util.stripTags($(el).text())
                });
            });
            var content = [h('h2', Messages.markdown_toc)];
            toc.forEach(function (obj) {
                var title = (obj.title || "").trim();
                if (!title) { return; }
                // Only include level 2 headings
                var level = obj.level;
                var a = h('a.cp-pad-toc-link', {
                    href: '#',
                });
                $(a).click(function (e) {
                    e.preventDefault();
                    e.stopPropagation();
                    if (!obj.el || UIElements.isVisible(obj.el, $inner)) { return; }
                    obj.el.scrollIntoView();
                });
                a.innerHTML = title;
                content.push(h('p.cp-pad-toc-'+level, a));
            });
            $toc.html('').append(content);
        }, 400);

        // apply patches, and try not to lose the cursor in the process!
        framework.onContentUpdate(function(hjson) {
            if (!Array.isArray(hjson)) { throw new Error(Messages.typeError); }
            var userDocStateDom = hjsonToDom(hjson);
            cursorStopped = true;

            userDocStateDom.setAttribute("contenteditable",
                inner.getAttribute('contenteditable'));

            restoreMediaTags(userDocStateDom, mediaTagMap);

            cursors.removeCursors(inner);

            // Deal with adjasent text nodes
            userDocStateDom.normalize();
            inner.normalize();

            $(userDocStateDom).find('span[data-cke-display-name="media-tag"]:empty').each(function(i, el) {
                $(el).remove();
            });

            // Get cursor position
            cursor.offsetUpdate();
            var oldText = inner.outerHTML;

            // Apply the changes
            var patch = (DD).diff(inner, userDocStateDom);
            (DD).apply(inner, patch);

            editor.fire('cp-wc'); // Update word count

            // Restore cursor position
            var newText = inner.outerHTML;
            var ops = ChainPad.Diff.diff(oldText, newText);
            cursor.restoreOffset(ops);

            setTimeout(function() {
                cursorStopped = false;
                updateCursor();
            }, 200);

            // MEDIATAG: Migrate old mediatags to the widget system
            $inner.find('media-tag:not(.cke_widget_element)').each(function(i, el) {
                var element = new window.CKEDITOR.dom.element(el);
                editor.widgets.initOn(element, 'mediatag');
            });

            displayMediaTags(framework, inner, mediaTagMap);

            // MEDIATAG: Initialize mediatag widgets inserted in the document by other users
            editor.widgets.checkWidgets();

            if (framework.isReadOnly()) {
                var $links = $inner.find('a');
                // off so that we don't end up with multiple identical handlers
                $links.off('click', openLink).on('click', openLink);
            }

            comments.onContentUpdate();

            updateTOC();
        });

        framework.setTextContentGetter(function() {
            var innerCopy = inner.cloneNode(true);
            displayMediaTags(framework, innerCopy, mediaTagMap);
            innerCopy.normalize();
            $(innerCopy).find('*').each(function(i, el) {
                $(el).append(' ');
            });
            var str = $(innerCopy).text();
            str = str.replace(/\s\s+/g, ' ');
            return str;
        });
        framework.setContentGetter(function() {
            $inner.find('span[data-cke-display-name="media-tag"]:empty').each(function(i, el) {
                $(el).remove();
            });

            // We have to remove the cursors before getting the content because they split
            // the text nodes and OT/ChainPad would freak out
            cursors.removeCursors(inner);

            comments.onContentUpdate();

            displayMediaTags(framework, inner, mediaTagMap);
            inner.normalize();
            var hjson = Hyperjson.fromDOM(inner, shouldSerialize, hjsonFilters);

            return hjson;
        });

        if (!framework.isReadOnly()) {
            addToolbarHideBtn(framework, $('.cke_toolbox_main'));
        } else {
            $('.cke_toolbox_main').hide();
        }

        framework.onReady(function(newPad) {
            editor.focus();

            if (!module.isMaximized) {
                module.isMaximized = true;
                $('iframe.cke_wysiwyg_frame').css('width', '');
                $('iframe.cke_wysiwyg_frame').css('height', '');
            }
            $('body').addClass('app-pad');

            if (newPad) {
                cursor.setToEnd();
            } else if (framework.isReadOnly()) {
                cursor.setToStart();
            }

            if (framework.isReadOnly()) {
                $inner.attr('contenteditable', 'false');
            }

            var fmConfig = {
                ckeditor: editor,
                dropArea: $inner,
                body: $('body'),
                onUploaded: function(ev, data) {
                    var parsed = Hash.parsePadUrl(data.url);
                    var secret = Hash.getSecrets('file', parsed.hash, data.password);
                    var fileHost = privateData.fileHost || privateData.origin;
                    var src = fileHost + Hash.getBlobPathFromHex(secret.channel);
                    var key = Hash.encodeBase64(secret.keys.cryptKey);
                    var mt = '<media-tag contenteditable="false" src="' + src + '" data-crypto-key="cryptpad:' + key + '"></media-tag>';
                    // MEDIATAG
                    var element = window.CKEDITOR.dom.element.createFromHtml(mt);
                    if (ev && ev.insertElement) {
                        ev.insertElement(element);
                    } else {
                        editor.insertElement(element);
                    }
                    editor.widgets.initOn(element, 'mediatag');
                }
            };
            var FM = window.APP.FM = framework._.sfCommon.createFileManager(fmConfig);

            editor.on('paste', function (ev) {
                try {
                    var files = ev.data.dataTransfer._.files;
                    files.forEach(function (f) {
                        FM.handleFile(f);
                    });
                    // If the paste data contains files, don't use the ckeditor default handlers
                    // ==> they would try to include either a remote image URL or a base64 image
                    if (files.length) {
                        ev.cancel();
                        ev.preventDefault();
                    }
                } catch (e) {
                    console.error(e);
                }
            });

            framework._.sfCommon.getAttribute(['pad', 'spellcheck'], function(err, data) {
                if (framework.isReadOnly()) { return; }
                if (data) {
                    $iframe.find('body').attr('spellcheck', true);
                }
            });

            framework._.sfCommon.isPadStored(function(err, val) {
                if (!val) { return; }
                var b64images = $inner.find('img[src^="data:image"]:not(.cke_reset)');
                if (b64images.length && framework._.sfCommon.isLoggedIn()) {
                    var no = h('button.cp-corner-cancel', Messages.cancel);
                    var yes = h('button.cp-corner-primary', Messages.ok);
                    var actions = h('div', [no, yes]);
                    var modal = UI.cornerPopup(Messages.pad_base64, actions, '', { big: true });
                    $(no).click(function() {
                        modal.delete();
                    });
                    $(yes).click(function() {
                        modal.delete();
                        b64images.each(function(i, el) {
                            var src = $(el).attr('src');
                            var blob = Util.dataURIToBlob(src);
                            var ext = '.' + (blob.type.split('/')[1] || 'png');
                            var name = (framework._.title.getTitle() || 'Pad') + '_image';
                            blob.name = name + ext;
                            var ev = {
                                insertElement: function(newEl) {
                                    var element = new window.CKEDITOR.dom.element(el);
                                    newEl.replace(element);
                                    setTimeout(framework.localChange);
                                }
                            };
                            window.APP.FM.handleFile(blob, ev);
                        });
                    });
                }
            });

            comments.ready();

            /*setTimeout(function () {
                $('iframe.cke_wysiwyg_frame').focus();
                editor.focus();
                console.log(editor);
                console.log(editor.focusManager);
                $(window).trigger('resize');
            });*/
        });

        framework.onDefaultContentNeeded(function() {
            inner.innerHTML = '<p></p>';
        });

        var importMediaTags = function(dom, cb) {
            var $dom = $(dom);
            $dom.find('media-tag').each(function(i, el) {
                $(el).empty();
            });
            cb($dom[0]);
        };
        framework.setFileImporter({ accept: 'text/html' }, function(content, f, cb) {
            importMediaTags(domFromHTML(content).body, function(dom) {
                cb(Hyperjson.fromDOM(dom));
            });
        }, true);

        framework.setFileExporter(Exporter.exts, function(cb, ext) {
            Exporter.main(inner, cb, ext);
        }, true);

        framework.setNormalizer(function(hjson) {
            return [
                'BODY',
                {
                    "class": "cke_editable cke_editable_themed cke_contents_ltr cke_show_borders",
                    "contenteditable": "true",
                    "spellcheck": "false"
                },
                hjson[2]
            ];
        });

        /* Display the cursor of other users and send our cursor */
        framework.setCursorGetter(cursors.cursorGetter);
        framework.onCursorUpdate(cursors.onCursorUpdate);
        inner.addEventListener('click', updateCursor);
        inner.addEventListener('keyup', updateCursor);


        /* hitting enter makes a new line, but places the cursor inside
            of the <br> instead of the <p>. This makes it such that you
            cannot type until you click, which is rather unnacceptable.
            If the cursor is ever inside such a <br>, you probably want
            to push it out to the parent element, which ought to be a
            paragraph tag. This needs to be done on keydown, otherwise
            the first such keypress will not be inserted into the P. */
        inner.addEventListener('keydown', cursor.brFix);

        /*
            CkEditor emits a change event when it detects new content in the editable area.
            Our problem is that this event is sent asynchronously and late after a keystroke.
            The result is that between the keystroke and the change event, chainpad may
            receive remote changes and so it can wipe the newly inserted content (because
            chainpad work synchronously), and the merged text is missing a few characters.
            To fix this, we have to call `framework.localChange` sooner. We can't listen for
            the "keypress" event because it is trigger before the character is inserted.
            The solution is the "input" event, triggered by the browser as soon as the
            character is inserted.
        */
        inner.addEventListener('input', function() {
            framework.localChange();
            updateCursor();
            editor.fire('cp-wc'); // Update word count
            updateTOC();
        });
        editor.on('change', function () {
            framework.localChange();
            updateTOC();
        });

        var wordCount = h('span.cp-app-pad-wordCount');
        $('.cke_toolbox_main').append(wordCount);
        editor.on('cp-wc-update', function() {
            if (!editor.wordCount || typeof(editor.wordCount.wordCount) === "undefined") {
                wordCount.innerText = '';
                return;
            }
            wordCount.innerText = Messages._getKey('pad_wordCount', [editor.wordCount.wordCount]);
        });

        // export the typing tests to the window.
        // call like `test = easyTest()`
        // terminate the test like `test.cancel()`
        window.easyTest = function() {
            cursor.update();
            //var start = cursor.Range.start;
            //var test = TypingTest.testInput(inner, start.el, start.offset, framework.localChange);
            var test = TypingTest.testPad(editor, framework.localChange);
            framework.localChange();
            return test;
        };


        // Fix the scrollbar if it's reset when clicking on a button (firefox only?)
        var buttonScrollTop;
        $('.cke_toolbox_main').find('.cke_button, .cke_combo_button').mousedown(function() {
            buttonScrollTop = $('iframe').contents().scrollTop();
            setTimeout(function() {
                $('iframe').contents().scrollTop(buttonScrollTop);
            });
        });


        $('.cke_toolbox_main').find('.cke_button').click(function() {
            var e = this;
            var classString = e.getAttribute('class');
            var classes = classString.split(' ').filter(function(c) {
                return /cke_button__/.test(c);
            });

            var id = classes[0];
            if (typeof(id) === 'string') {
                framework.feedback(id.toUpperCase());
            }
        });

        framework.start();
    };

    var main = function() {
        var Ckeditor;
        var editor;
        var framework;

        nThen(function(waitFor) {
            Framework.create({
                toolbarContainer: '#cp-app-pad-toolbar',
                contentContainer: '#cp-app-pad-editor',
                patchTransformer: ChainPad.NaiveJSONTransformer,
                /*thumbnail: {
                    getContainer: function () { return $('iframe').contents().find('html')[0]; },
                    filter: function (el, before) {
                        if (before) {
                            module.cursor.update();
                            $(el).parents().css('overflow', 'visible');
                            $(el).css('max-width', '1200px');
                            $(el).css('max-height', Math.max(600, $(el).width()) + 'px');
                            $(el).css('overflow', 'hidden');
                            $(el).find('body').css('background-color', 'transparent');
                            return;
                        }
                        $(el).parents().css('overflow', '');
                        $(el).css('max-width', '');
                        $(el).css('max-height', '');
                        $(el).css('overflow', '');
                        $(el).find('body').css('background-color', '#fff');
                        var sel = module.cursor.makeSelection();
                        var range = module.cursor.makeRange();
                        module.cursor.fixSelection(sel, range);
                    }
                }*/
            }, waitFor(function(fw) { window.APP.framework = framework = fw; }));

            nThen(function(waitFor) {
                ckEditorAvailable(waitFor(function(ck) {
                    Ckeditor = ck;
                    require(['/pad/wysiwygarea-plugin.js'], waitFor());
                }));
                $(waitFor());
            }).nThen(function(waitFor) {
                Ckeditor.config.toolbarCanCollapse = true;
                if (screen.height < 800) {
                    Ckeditor.config.toolbarStartupExpanded = false;
                    $('meta[name=viewport]').attr('content',
                        'width=device-width, initial-scale=1.0, user-scalable=no');
                } else {
                    $('meta[name=viewport]').attr('content',
                        'width=device-width, initial-scale=1.0, user-scalable=yes');
                }
                // Used in ckeditor-config.js
                Ckeditor.CRYPTPAD_URLARGS = ApiConfig.requireConf.urlArgs;
                Ckeditor._mediatagTranslations = {
                    title: Messages.pad_mediatagTitle,
                    width: Messages.pad_mediatagWidth,
                    height: Messages.pad_mediatagHeight,
                    ratio: Messages.pad_mediatagRatio,
                    border: Messages.pad_mediatagBorder,
                    preview: Messages.pad_mediatagPreview,
                    'import': Messages.pad_mediatagImport,
                    options: Messages.pad_mediatagOptions
                };
                Ckeditor._commentsTranslations = {
                    comment: Messages.comments_comment,
                };
                Ckeditor.plugins.addExternal('mediatag', '/pad/', 'mediatag-plugin.js');
                Ckeditor.plugins.addExternal('blockbase64', '/pad/', 'disable-base64.js');
                Ckeditor.plugins.addExternal('comments', '/pad/', 'comment.js');
                Ckeditor.plugins.addExternal('wordcount', '/pad/wordcount/', 'plugin.js');

/*  CKEditor4 is, by default, incompatible with strong CSP settings due to the
    way it loads a variety of resources and event handlers by injecting HTML
    via the innerHTML API.

    In most cases those handlers just call a function with an id, so there's no
    strong case for why it should be done this way except that lots of code depends
    on this behaviour. These handlers all stop working when we enable our default CSP,
    but fortunately the code is simple enough that we can use regex to grab the id
    from the inline code and call the relevant function directly, preserving the
    intended behaviour while preventing malicious code injection.

    Unfortunately, as long as the original code is still present the console
    fills up with CSP warnings saying that inline scripts were blocked.
    The code below overrides CKEditor's default `setHtml` method to include
    a string.replace call which will rewrite various inline event handlers from
    onevent to oonevent.. rendering them invalid as scripts and preventing
    some needless noise from showing up in the console.

    YAY!
*/
                Ckeditor.dom.element.prototype.setHtml = function(a){
                    if (/callFunction/.test(a)) {
                        a = a.replace(/on(mousedown|blur|keydown|focus|click|dragstart|mouseover|mouseout)/g, function (value) {
                            return 'o' + value;
                        });
                    }
                    this.$.innerHTML = a;
                    return a;
                };

                module.ckeditor = editor = Ckeditor.replace('editor1', {
                    customConfig: '/customize/ckeditor-config.js',
                });

                editor.addCommand('pagemode', {
                    exec: function() {
                        if (!framework) { return; }
                        var $contentContainer = $('#cke_1_contents');
                        var $button = $('.cke_button__pagemode');
                        var isLarge = $button.hasClass('cke_button_on');
                        if (isLarge) {
                            $button.addClass('cke_button_off').removeClass('cke_button_on');
                            $contentContainer.addClass('cke_body_width');
                        } else {
                            $button.addClass('cke_button_on').removeClass('cke_button_off');
                            $contentContainer.removeClass('cke_body_width');
                        }
                        framework._.sfCommon.setAttribute(['pad', 'width'], isLarge);
                    }
                });
                editor.ui.addButton('PageMode', {
                    label: Messages.pad_useFullWidth,
                    command: 'pagemode',
                    icon: '/pad/icons/arrows-h.png',
                    toolbar: 'document,60'
                });

                editor.on('instanceReady', waitFor());
            }).nThen(function() {
                var _getPath = Ckeditor.plugins.getPath;
                Ckeditor.plugins.getPath = function (name) {
                    if (name === 'preview') {
                        return window.location.origin + "/bower_components/ckeditor/plugins/preview/";
                    }
                    return _getPath(name);
                };
                window.__defineGetter__('_cke_htmlToLoad', function() {});
                editor.plugins.mediatag.import = function($mt) {
                    framework._.sfCommon.importMediaTag($mt);
                };
                Links.init(Ckeditor, editor);
            }).nThen(function() {
                // Move ckeditor parts to have a structure like the other apps
                var $contentContainer = $('#cke_1_contents');
                var $mainContainer = $('#cke_editor1 > .cke_inner');
                var $ckeToolbar = $('#cke_1_top').find('.cke_toolbox_main');
                $mainContainer.prepend($ckeToolbar.addClass('cke_reset_all'));
                $contentContainer.append(h('div#cp-app-pad-comments'));
                $contentContainer.prepend(h('div#cp-app-pad-toc'));
                $ckeToolbar.find('.cke_button__image_icon').parent().hide();
            }).nThen(waitFor());

        }).nThen(function(waitFor) {
            require(['/pad/csp.js'], waitFor());
        }).nThen(function( /*waitFor*/ ) {

            function launchAnchorTest(test) {
                // -------- anchor test: make sure the exported anchor contains <a name="...">  -------
                console.log('---- anchor test: make sure the exported anchor contains <a name="...">  -----.');

                function tryAndTestExport() {
                    console.log("Starting tryAndTestExport.");
                    editor.on('dialogShow', function(evt) {
                        console.log("Anchor dialog detected.");
                        var dialog = evt.data;
                        $(dialog.parts.contents.$).find("input").val('xx-' + Math.round(Math.random() * 1000));
                        dialog.click(window.CKEDITOR.dialog.okButton(editor).id);
                    });
                    var existingText = editor.getData();
                    editor.insertText("A bit of text");
                    console.log("Launching anchor command.");
                    editor.execCommand(editor.ui.get('Anchor').command);
                    console.log("Anchor command launched.");

                    var waitH = window.setInterval(function() {
                        console.log("Waited 2s for the dialog to appear");
                        var anchors = window.CKEDITOR.plugins["link"].getEditorAnchors(editor);
                        if (!anchors || anchors.length === 0) {
                            test.fail("No anchors found. Please adjust document");
                        } else {
                            console.log(anchors.length + " anchors found.");
                            var exported = Exporter.getHTML(window.inner);
                            console.log("Obtained exported: " + exported);
                            var allFound = true;
                            for (var i = 0; i < anchors.length; i++) {
                                var anchor = anchors[i];
                                console.log("Anchor " + anchor.name);
                                var expected = "<a id=\"" + anchor.id + "\" name=\"" + anchor.name + "\" ";
                                var found = exported.indexOf(expected) >= 0;
                                console.log("Found " + expected + " " + found + ".");
                                allFound = allFound && found;
                            }

                            console.log("Cleaning up.");
                            if (allFound) {
                                // clean-up
                                editor.execCommand('undo');
                                editor.execCommand('undo');
                                var nint = window.setInterval(function() {
                                    console.log("Waiting for undo to yield same result.");
                                    if (existingText === editor.getData()) {
                                        window.clearInterval(nint);
                                        test.pass();
                                    }
                                }, 500);
                            } else {
                                test.fail("Not all expected a elements found for document at " + window.top.location + ".");
                            }
                        }
                        window.clearInterval(waitH);
                    }, 2000);


                }
                var intervalHandle = window.setInterval(function() {
                    if (editor.status === "ready") {
                        window.clearInterval(intervalHandle);
                        console.log("Editor is ready.");
                        tryAndTestExport();
                    } else {
                        console.log("Waiting for editor to be ready.");
                    }
                }, 100);
            }
            Test(function(test) {

                launchAnchorTest(test);
            });
            andThen2(editor, Ckeditor, framework);
        });
    };
    main();
});
