"""Third-party tracker and ad-SDK signatures for the tracker analyzer.

Each entry maps a display name to class-path prefixes that appear as DEX type
descriptors when the SDK is bundled. Presence indicates data collection surface,
not a vulnerability. Signatures are a curated subset of common trackers.
"""

from __future__ import annotations

TRACKERS: dict[str, tuple[str, ...]] = {
    "Google Firebase Analytics": ("Lcom/google/firebase/analytics",),
    "Google Crashlytics": ("Lcom/google/firebase/crashlytics", "Lcom/crashlytics"),
    "Google AdMob": ("Lcom/google/android/gms/ads",),
    "Google Tag Manager": ("Lcom/google/android/gms/tagmanager",),
    "Facebook Login/Ads": ("Lcom/facebook/ads", "Lcom/facebook/login", "Lcom/facebook/appevents"),
    "Facebook Analytics": ("Lcom/facebook/analytics",),
    "Flurry": ("Lcom/flurry",),
    "AppsFlyer": ("Lcom/appsflyer",),
    "Adjust": ("Lcom/adjust/sdk",),
    "Branch": ("Lio/branch",),
    "Mixpanel": ("Lcom/mixpanel",),
    "Amplitude": ("Lcom/amplitude",),
    "Segment": ("Lcom/segment/analytics",),
    "Braze/Appboy": ("Lcom/appboy", "Lcom/braze"),
    "OneSignal": ("Lcom/onesignal",),
    "Sentry": ("Lio/sentry",),
    "Bugsnag": ("Lcom/bugsnag",),
    "New Relic": ("Lcom/newrelic",),
    "Unity Ads": ("Lcom/unity3d/ads",),
    "AppLovin": ("Lcom/applovin",),
    "IronSource": ("Lcom/ironsource",),
    "Vungle": ("Lcom/vungle",),
    "Chartboost": ("Lcom/chartboost",),
    "InMobi": ("Lcom/inmobi",),
    "MoPub": ("Lcom/mopub",),
    "Yandex Metrica": ("Lcom/yandex/metrica",),
    "Umeng": ("Lcom/umeng",),
    "Tencent Bugly": ("Lcom/tencent/bugly",),
    "Kochava": ("Lcom/kochava",),
    "Tealium": ("Lcom/tealium",),
}
