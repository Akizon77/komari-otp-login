(function () {
  "use strict";

  var apiRoot = "/api/komari-otp-login";
  var messages = {
    en: {
      login: "Sign in with one-time code",
      title: "One-time code sign-in",
      usernameCopy: "Enter your username",
      usernamePlaceholder: "Username",
      next: "Next",
      codeCopy: "A code will be sent to you. It expires in 3 minutes.",
      trouble: "Having trouble?",
      resend: "Resend code",
      resendIn: "Resend in {seconds}s",
      cancel: "Cancel",
      sending: "Sending...",
      notificationFailed: "The notification could not be sent. Check the notification channel configuration.",
      invalidCode: "The code is incorrect.",
      expired: "The code has expired. Send a new one.",
      attempts: "Too many attempts. Send a new code.",
      resendSoon: "Please wait before sending another code.",
      invalidUsername: "The username is incorrect.",
      ipRateLimited: "Too many attempts from this IP address. Try again in 15 minutes.",
      failed: "The sign-in request could not be completed.",
      codeDigit: "Code character {index}",
    },
    "zh-CN": {
      login: "一次性验证码登录",
      title: "验证码登录",
      usernameCopy: "请输入您的用户名",
      usernamePlaceholder: "用户名",
      next: "下一步",
      codeCopy: "验证码将发送给您，有效期为3分钟。",
      trouble: "遇到问题？",
      resend: "重发验证码",
      resendIn: "{seconds} 秒后重发",
      cancel: "取消",
      sending: "发送中...",
      notificationFailed: "通知发送失败，请检查通知渠道配置。",
      invalidCode: "验证码不正确。",
      expired: "验证码已过期，请重新发送。",
      attempts: "尝试次数过多，请重新发送验证码。",
      resendSoon: "请稍后再发送验证码。",
      invalidUsername: "用户名不正确。",
      ipRateLimited: "此 IP 尝试次数过多，请在 15 分钟后重试。",
      failed: "无法完成登录请求。",
      codeDigit: "验证码第 {index} 位",
    },
  };

  function locale() {
    var value = localStorage.getItem("i18nextLng") || document.documentElement.lang || navigator.language || "en";
    return /^zh/i.test(value) ? "zh-CN" : "en";
  }

  function t(key, values) {
    var text = messages[locale()][key] || messages.en[key] || key;
    return text.replace(/\{(\w+)\}/g, function (_, name) {
      return values && values[name] !== undefined ? String(values[name]) : "";
    });
  }

  function api(path, body) {
    return fetch(apiRoot + path, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    }).then(function (response) {
      return response.json().catch(function () {
        return { ok: false, code: "internal_error" };
      }).then(function (data) {
        if (!response.ok || data.ok !== true) {
          var error = new Error(data.code || "internal_error");
          error.code = data.code;
          throw error;
        }
        return data;
      });
    });
  }

  function element(tag, className, text) {
    var node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined) {
      node.textContent = text;
    }
    return node;
  }

  function button(label, soft, color) {
    var node = element(
      "button",
      "rt-reset rt-BaseButton rt-r-size-2 " + (soft ? "rt-variant-soft" : "rt-variant-solid") + " rt-Button",
      label,
    );
    node.type = "button";
    if (color) {
      node.setAttribute("data-accent-color", color);
    }
    return node;
  }

  function errorMessage(error) {
    var code = error && error.code ? error.code : "";
    var key = {
      notification_failed: "notificationFailed",
      invalid_code: "invalidCode",
      code_expired: "expired",
      too_many_attempts: "attempts",
      resend_too_soon: "resendSoon",
      invalid_username: "invalidUsername",
      ip_rate_limited: "ipRateLimited",
    }[code];
    return key ? t(key) : t("failed");
  }

  function loginRedirect() {
    var fallback = "/admin/dashboard";
    try {
      var redirect = new URLSearchParams(window.location.search).get("redirect") || fallback;
      if (redirect.charAt(0) !== "/" || redirect.charAt(1) === "/" || redirect.indexOf("\\") !== -1) {
        return fallback;
      }
      var target = new URL(redirect, window.location.origin);
      return target.origin === window.location.origin ? target.pathname + target.search + target.hash : fallback;
    } catch (_) {
      return fallback;
    }
  }

  function showDialog() {
    if (document.querySelector(".km-otp-login-dialog-overlay")) {
      return;
    }

    var overlay = element("div", "rt-BaseDialogOverlay rt-DialogOverlay km-otp-login-dialog-overlay");
    var scroll = element("div", "rt-BaseDialogScroll rt-DialogScroll");
    var padding = element("div", "rt-BaseDialogScrollPadding rt-DialogScrollPadding rt-r-align-center");
    var dialog = element("section", "rt-BaseDialogContent rt-DialogContent rt-r-size-3 km-otp-login-dialog");
    overlay.setAttribute("data-state", "open");
    dialog.setAttribute("data-state", "open");
    dialog.setAttribute("role", "dialog");
    dialog.setAttribute("aria-modal", "true");
    dialog.setAttribute("aria-labelledby", "km-otp-login-title");
    dialog.tabIndex = -1;

    var title = element("h2", "rt-Heading rt-r-size-5 rt-r-mb-3", t("title"));
    title.id = "km-otp-login-title";
    dialog.appendChild(title);

    var usernameStep = element("div", "km-otp-login-step");
    usernameStep.appendChild(element("p", "rt-Text rt-r-size-3 km-otp-login-copy", t("usernameCopy")));
    var usernameRoot = element("div", "rt-TextFieldRoot rt-r-size-2 rt-variant-surface km-otp-login-username-root");
    var username = element("input", "rt-reset rt-TextFieldInput");
    username.type = "text";
    username.autocomplete = "username";
    username.maxLength = 100;
    username.placeholder = t("usernamePlaceholder");
    username.setAttribute("aria-label", t("usernamePlaceholder"));
    usernameRoot.appendChild(username);
    usernameStep.appendChild(usernameRoot);
    var usernameActions = element("div", "km-otp-login-actions");
    var next = button(t("next"), false, "");
    var usernameCancel = button(t("cancel"), true, "gray");
    usernameActions.appendChild(next);
    usernameActions.appendChild(usernameCancel);
    usernameStep.appendChild(usernameActions);
    dialog.appendChild(usernameStep);

    var codeStep = element("div", "km-otp-login-step km-otp-login-code-step");
    codeStep.hidden = true;
    codeStep.appendChild(element("p", "rt-Text rt-r-size-3 km-otp-login-copy", t("codeCopy")));
    var codeInputsRoot = element("div", "km-otp-login-code-inputs");
    var codeInputs = [];
    for (var index = 0; index < 8; index += 1) {
      var input = element("input", "rt-reset rt-TextFieldInput km-otp-login-code-input");
      input.type = "text";
      input.inputMode = "text";
      input.autocomplete = index === 0 ? "one-time-code" : "off";
      input.maxLength = 8;
      input.setAttribute("aria-label", t("codeDigit", { index: index + 1 }));
      codeInputs.push(input);
      codeInputsRoot.appendChild(input);
    }
    codeStep.appendChild(codeInputsRoot);
    codeStep.appendChild(element("p", "rt-Text rt-r-size-2 km-otp-login-trouble", t("trouble")));
    var codeActions = element("div", "km-otp-login-actions");
    var resend = button(t("resend"), true, "");
    var codeCancel = button(t("cancel"), true, "gray");
    codeActions.appendChild(resend);
    codeActions.appendChild(codeCancel);
    codeStep.appendChild(codeActions);
    dialog.appendChild(codeStep);

    var note = element("div", "km-otp-login-error");
    note.setAttribute("role", "alert");
    dialog.appendChild(note);
    padding.appendChild(dialog);
    scroll.appendChild(padding);
    overlay.appendChild(scroll);

    var timer = null;
    var isVerifying = false;

    function close() {
      if (timer) {
        window.clearInterval(timer);
      }
      document.removeEventListener("keydown", onKeydown);
      overlay.remove();
    }

    function onKeydown(event) {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
      }
    }

    function setError(error) {
      note.textContent = error ? errorMessage(error) : "";
    }

    function setCodeInputsDisabled(disabled) {
      codeInputs.forEach(function (input) {
        input.disabled = disabled;
      });
    }

    function codeValue() {
      return codeInputs.map(function (input) {
        return input.value;
      }).join("");
    }

    function focusCodeInput(index) {
      if (codeInputs[index]) {
        codeInputs[index].focus();
        codeInputs[index].select();
      }
    }

    function resetCodeInputs() {
      codeInputs.forEach(function (input) {
        input.value = "";
      });
      isVerifying = false;
    }

    function verifyWhenComplete() {
      if (isVerifying || codeValue().length !== codeInputs.length) {
        return;
      }
      isVerifying = true;
      setError(null);
      setCodeInputsDisabled(true);
      api("/verify", { username: username.value.trim(), code: codeValue() })
        .then(function () {
          window.location.replace(loginRedirect());
        })
        .catch(function (error) {
          isVerifying = false;
          setCodeInputsDisabled(false);
          setError(error);
          focusCodeInput(codeInputs.length - 1);
        });
    }

    function fillCode(value) {
      var characters = value.replace(/[^a-z0-9]/gi, "").toUpperCase().slice(0, codeInputs.length).split("");
      codeInputs.forEach(function (input, index) {
        input.value = characters[index] || "";
      });
      var firstEmpty = characters.length < codeInputs.length ? characters.length : codeInputs.length - 1;
      focusCodeInput(firstEmpty);
      verifyWhenComplete();
    }

    function startCooldown(seconds) {
      var remaining = Math.max(0, Number(seconds) || 0);
      function render() {
        resend.disabled = remaining > 0;
        resend.textContent = remaining > 0 ? t("resendIn", { seconds: remaining }) : t("resend");
      }
      render();
      if (timer) {
        window.clearInterval(timer);
      }
      timer = window.setInterval(function () {
        remaining -= 1;
        render();
        if (remaining <= 0) {
          window.clearInterval(timer);
          timer = null;
        }
      }, 1000);
    }

    function sendCode(onSuccess) {
      setError(null);
      api("/send", { username: username.value.trim() })
        .then(function (data) {
          startCooldown(data.resend_in);
          resetCodeInputs();
          onSuccess();
        })
        .catch(function (error) {
          setError(error);
          onSuccess(error);
        });
    }

    function showCodeStep() {
      usernameStep.hidden = true;
      codeStep.hidden = false;
      window.setTimeout(function () {
        focusCodeInput(0);
      }, 0);
    }

    usernameCancel.addEventListener("click", close);
    codeCancel.addEventListener("click", close);
    function beginCodeRequest() {
      if (next.disabled) {
        return;
      }
      next.disabled = true;
      next.textContent = t("sending");
      sendCode(function (error) {
        if (error) {
          next.disabled = false;
          next.textContent = t("next");
          return;
        }
        showCodeStep();
      });
    }
    next.addEventListener("click", beginCodeRequest);
    username.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" || event.isComposing || next.disabled) {
        return;
      }
      event.preventDefault();
      beginCodeRequest();
    });
    resend.addEventListener("click", function () {
      resend.disabled = true;
      resend.textContent = t("sending");
      sendCode(function (error) {
        if (error) {
          resend.disabled = false;
          resend.textContent = t("resend");
          return;
        }
        focusCodeInput(0);
      });
    });
    codeInputs.forEach(function (input, index) {
      input.addEventListener("input", function () {
        var value = input.value.replace(/[^a-z0-9]/gi, "").toUpperCase();
        if (value.length > 1) {
          fillCode(value);
          return;
        }
        input.value = value;
        if (value && index < codeInputs.length - 1) {
          focusCodeInput(index + 1);
        }
        verifyWhenComplete();
      });
      input.addEventListener("keydown", function (event) {
        if (event.key === "Backspace" && !input.value && index > 0) {
          event.preventDefault();
          codeInputs[index - 1].value = "";
          focusCodeInput(index - 1);
        }
      });
      input.addEventListener("paste", function (event) {
        event.preventDefault();
        fillCode(event.clipboardData.getData("text"));
      });
    });

    document.addEventListener("keydown", onKeydown);
    var rootNode = document.querySelector(".radix-themes") || document.body;
    rootNode.appendChild(overlay);
    window.setTimeout(function () {
      username.focus();
    }, 0);
  }

  function mountLoginButtons() {
    document.querySelectorAll(".km-login-card, .km-login-dialog, .km-restricted-login-dialog").forEach(function (dialog) {
      if (dialog.querySelector(".km-otp-login-button")) {
        return;
      }
      var form = dialog.querySelector(".km-login-form, .km-restricted-login-form");
      if (!form) {
        return;
      }
      var container = form.querySelector(".rt-Flex") || form;
      var login = button(t("login"), true, "");
      login.classList.add("km-otp-login-button", "w-full");
      login.addEventListener("click", showDialog);
      container.appendChild(login);
    });
  }

  var observer = new MutationObserver(mountLoginButtons);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  mountLoginButtons();
})();
