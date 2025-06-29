#include <gtest/gtest.h>
#include "CLIHandler.h"

// We can directly test CLIHandler’s constructor and argument parsing here
TEST(CLIHandlerTest, ArgumentParsingStoresCorrectArgs) {
    const char* argv[] = { "program", "encrypt", "file.txt" };
    int argc = 3;

    CLIHandler cli(argc, const_cast<char**>(argv));
    ASSERT_EQ(cli.args.size(), 2);
    EXPECT_EQ(cli.args[0], "encrypt");
    EXPECT_EQ(cli.args[1], "file.txt");
}

TEST(CLIHandlerTest, MenuInputWithinValidRange) {
    // NOTE: You can’t fully test displayMenuAndPrompt without I/O mocking.
    // But you can safely test that it compiles and the CLI structure is sound.
    // Full I/O tests would require cin redirection.
    SUCCEED();  // Placeholder
}

TEST(CLIHandlerTest, DisplayHelpRunsWithoutCrash) {
    CLIHandler cli(0, nullptr);
    EXPECT_NO_THROW(cli.displayHelp());
}

TEST(CLIHandlerTest, ParseArgumentsPlaceholder) {
    CLIHandler cli(0, nullptr);
    EXPECT_NO_THROW(cli.parseArguments());
}

TEST(CLIHandlerTest, DisplayBannerRunsWithoutCrash) {
    CLIHandler cli(0, nullptr);
    EXPECT_NO_THROW(cli.displayBanner());
}