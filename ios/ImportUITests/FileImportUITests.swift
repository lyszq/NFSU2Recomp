import XCTest

final class FileImportUITests: XCTestCase {
    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launchArguments = ["-AppleLanguages", "(en)", "-AppleLocale", "en_US"]
        app.launch()
    }

    func testExecutablePickerCancelsAndCanBeOpenedAgain() throws {
        let selectExecutable = app.buttons["select-game-executable"]
        XCTAssertTrue(selectExecutable.waitForExistence(timeout: 15),
                      "The diagnostic setup screen must expose the production executable button.")
        scrollIntoView(selectExecutable)
        XCTAssertTrue(selectExecutable.isHittable,
                      "Scroll the diagnostic page until the production button can be tapped.")

        selectExecutable.tap()
        cancelFilesPicker(named: "first Files picker")

        XCTAssertTrue(selectExecutable.waitForExistence(timeout: 10),
                      "Cancel should return to the diagnostic screen.")
        scrollIntoView(selectExecutable)
        XCTAssertTrue(selectExecutable.isHittable,
                      "The executable route should be ready after cancellation.")

        selectExecutable.tap()
        cancelFilesPicker(named: "reopened Files picker")

        XCTAssertTrue(selectExecutable.waitForExistence(timeout: 10),
                      "Canceling the reopened picker should also return to the diagnostic screen.")
        XCTAssertTrue(selectExecutable.isHittable,
                      "The executable route should remain interactive after the second cancellation.")
        attachScreenshot(named: "picker-cancel-reopen-complete")
    }

    private func cancelFilesPicker(named name: String) {
        let cancelButton = app.buttons["Cancel"]
        let browseButton = app.buttons["Browse"]
        let browseTitle = app.navigationBars["Browse"]

        let cancelVisible = cancelButton.waitForExistence(timeout: 30)
        let browseVisible = browseButton.exists || browseTitle.exists
        XCTAssertTrue(cancelVisible || browseVisible,
                      "The system Files picker should show Cancel or Browse for \(name).")
        XCTAssertTrue(cancelVisible,
                      "The system Files picker must expose Cancel so the route can be tested after dismissal.")
        attachScreenshot(named: name)
        cancelButton.tap()
    }

    private func scrollIntoView(_ element: XCUIElement) {
        let scrollView = app.scrollViews.firstMatch
        for _ in 0..<8 {
            if element.isHittable { return }
            guard scrollView.exists else { return }
            scrollView.swipeUp()
        }
    }

    private func attachScreenshot(named name: String) {
        let attachment = XCTAttachment(screenshot: app.screenshot())
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
